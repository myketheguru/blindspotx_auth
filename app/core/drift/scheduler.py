"""
Drift Detection Scheduler
------------------------
This module provides scheduling capabilities for drift detection jobs,
enabling automated and periodic monitoring of configuration changes.

Features:
- Asynchronous scheduling using asyncio
- Configurable intervals and retry policies
- Comprehensive error handling and logging
- Health monitoring and status reporting
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Awaitable, Tuple
import random
import signal
import functools
from enum import Enum

from app.core.config import settings

logger = logging.getLogger(__name__)

# Scheduler health status
class SchedulerStatus(str, Enum):
    """Health status of the scheduler."""
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class JobStatus(str, Enum):
    """Status of an individual job."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"

# Global state
_scheduler_status = SchedulerStatus.STOPPED
_scheduler_tasks = {}
_job_history = []
_job_stats = {
    "total_runs": 0,
    "successful_runs": 0,
    "failed_runs": 0,
    "last_run_time": None,
    "last_success_time": None,
    "last_failure_time": None,
    "average_duration": 0,
}
_scheduler_health = {
    "status": SchedulerStatus.STOPPED,
    "uptime": 0,
    "start_time": None,
}

# Constants
MAX_JOB_HISTORY = 100
MAX_RETRY_COUNT = 3
BASE_RETRY_DELAY = 5  # seconds
JITTER_FACTOR = 0.2  # Add up to 20% jitter to avoid thundering herd


async def _run_with_retry(
    job_func: Callable[[], Awaitable[Any]], 
    job_name: str,
    max_retries: int = MAX_RETRY_COUNT
) -> Tuple[bool, Any, Optional[Exception]]:
    """
    Run a job with retry logic using exponential backoff.
    
    Args:
        job_func: Async function to execute
        job_name: Name of the job for logging
        max_retries: Maximum number of retry attempts
        
    Returns:
        Tuple of (success, result, exception)
    """
    retry_count = 0
    last_exception = None
    
    while retry_count <= max_retries:
        try:
            if retry_count > 0:
                logger.info(f"Retry attempt {retry_count} for job {job_name}")
                
            start_time = time.time()
            result = await job_func()
            duration = time.time() - start_time
            
            # Success
            logger.info(f"Job {job_name} completed successfully in {duration:.2f}s")
            return True, result, None
            
        except Exception as e:
            retry_count += 1
            last_exception = e
            logger.warning(f"Job {job_name} failed: {str(e)}")
            
            if retry_count <= max_retries:
                # Calculate retry delay with exponential backoff and jitter
                delay = BASE_RETRY_DELAY * (2 ** (retry_count - 1))
                jitter = delay * JITTER_FACTOR * random.random()
                total_delay = delay + jitter
                
                logger.info(f"Will retry job {job_name} in {total_delay:.2f} seconds")
                await asyncio.sleep(total_delay)
            else:
                logger.error(f"Job {job_name} failed after {max_retries} retries: {str(e)}")
    
    return False, None, last_exception


async def _job_wrapper(
    job_func: Callable[[], Awaitable[Any]], 
    job_name: str,
    interval_seconds: int
) -> None:
    """
    Wrapper for scheduled jobs that handles execution, logging, and retries.
    
    Args:
        job_func: The async function to execute
        job_name: Name of the job for logging
        interval_seconds: Interval between job runs in seconds
    """
    global _job_stats, _job_history
    
    logger.info(f"Scheduled job {job_name} starting with interval of {interval_seconds}s")
    
    while _scheduler_status in (SchedulerStatus.STARTING, SchedulerStatus.RUNNING):
        job_start_time = datetime.utcnow()
        
        # Record job start in history
        job_record = {
            "name": job_name,
            "status": JobStatus.RUNNING,
            "start_time": job_start_time,
            "end_time": None,
            "duration": None,
            "error": None
        }
        _job_history.append(job_record)
        _job_history = _job_history[-MAX_JOB_HISTORY:]  # Keep history bounded
        
        # Run job with retry logic
        try:
            _job_stats["total_runs"] += 1
            success, result, error = await _run_with_retry(job_func, job_name)
            
            job_end_time = datetime.utcnow()
            duration = (job_end_time - job_start_time).total_seconds()
            
            # Update job record
            job_record["end_time"] = job_end_time
            job_record["duration"] = duration
            
            # Update stats
            _job_stats["last_run_time"] = job_end_time
            
            # Calculate rolling average duration
            if _job_stats["average_duration"] == 0:
                _job_stats["average_duration"] = duration
            else:
                _job_stats["average_duration"] = (
                    _job_stats["average_duration"] * 0.9 + duration * 0.1
                )
            
            if success:
                _job_stats["successful_runs"] += 1
                _job_stats["last_success_time"] = job_end_time
                job_record["status"] = JobStatus.SUCCEEDED
                logger.info(f"Job {job_name} succeeded in {duration:.2f}s")
            else:
                _job_stats["failed_runs"] += 1
                _job_stats["last_failure_time"] = job_end_time
                job_record["status"] = JobStatus.FAILED
                job_record["error"] = str(error)
                logger.error(f"Job {job_name} failed after retries: {str(error)}")
                
        except Exception as e:
            job_end_time = datetime.utcnow()
            duration = (job_end_time - job_start_time).total_seconds()
            
            _job_stats["failed_runs"] += 1
            _job_stats["last_failure_time"] = job_end_time
            _job_stats["last_run_time"] = job_end_time
            
            job_record["status"] = JobStatus.FAILED
            job_record["end_time"] = job_end_time
            job_record["duration"] = duration
            job_record["error"] = str(e)
            
            logger.exception(f"Unexpected error in job {job_name}: {str(e)}")
        
        # Sleep until next interval
        try:
            # Add small jitter to avoid thundering herd
            jitter = interval_seconds * JITTER_FACTOR * random.random()
            wait_time = interval_seconds + jitter
            logger.debug(f"Job {job_name} sleeping for {wait_time:.2f}s until next run")
            await asyncio.sleep(wait_time)
        except asyncio.CancelledError:
            logger.info(f"Job {job_name} cancelled during sleep")
            job_record["status"] = JobStatus.CANCELLED
            break

    logger.info(f"Job {job_name} exiting")


async def schedule_drift_detection(
    interval_seconds: Optional[int] = None, 
    job_name: str = "drift_detection"
) -> None:
    """
    Schedule the drift detection job to run at specified intervals.
    
    Args:
        interval_seconds: Time between drift detection runs in seconds (default: from settings)
        job_name: Name to identify this job in logs and metrics
    """
    from app.core.drift.detector import detect_drift
    
    if not interval_seconds:
        interval_seconds = getattr(settings, "DRIFT_DETECTION_INTERVAL", 1800)  # Default: 30 minutes
    
    logger.info(f"Scheduling drift detection job to run every {interval_seconds} seconds")
    
    if _scheduler_status != SchedulerStatus.RUNNING:
        logger.warning("Scheduler is not running, job will not start until scheduler is started")
        return
    
    # Stop existing job if it exists
    if job_name in _scheduler_tasks and not _scheduler_tasks[job_name].done():
        logger.info(f"Stopping existing {job_name} job")
        _scheduler_tasks[job_name].cancel()
        try:
            await _scheduler_tasks[job_name]
        except asyncio.CancelledError:
            pass
    
    # Create and start new job
    task = asyncio.create_task(
        _job_wrapper(detect_drift, job_name, interval_seconds)
    )
    _scheduler_tasks[job_name] = task
    
    logger.info(f"Drift detection job {job_name} scheduled")


def start_scheduler() -> None:
    """
    Start the scheduler to enable background jobs.
    
    This should be called during application startup.
    """
    global _scheduler_status, _scheduler_health
    
    if _scheduler_status in (SchedulerStatus.RUNNING, SchedulerStatus.STARTING):
        logger.warning("Scheduler is already running or starting")
        return
    
    logger.info("Starting drift detection scheduler")
    _scheduler_status = SchedulerStatus.STARTING
    _scheduler_health["status"] = SchedulerStatus.STARTING
    _scheduler_health["start_time"] = datetime.utcnow()
    
    # Set up signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, RuntimeError):
            # Can't set signals in threads, ignore
            pass
    
    _scheduler_status = SchedulerStatus.RUNNING
    _scheduler_health["status"] = SchedulerStatus.RUNNING
    logger.info("Drift detection scheduler started")


def _signal_handler(signum, frame):
    """Handle termination signals for graceful shutdown."""
    logger.info(f"Received signal {signum}, initiating scheduler shutdown")
    asyncio.create_task(stop_scheduler())


async def stop_scheduler() -> None:
    """
    Stop the scheduler and all running jobs gracefully.
    
    This should be called during application shutdown.
    """
    global _scheduler_status, _scheduler_health
    
    if _scheduler_status in (SchedulerStatus.STOPPED, SchedulerStatus.STOPPING):
        logger.warning("Scheduler is already stopped or stopping")
        return
    
    logger.info("Stopping drift detection scheduler")
    _scheduler_status = SchedulerStatus.STOPPING
    _scheduler_health["status"] = SchedulerStatus.STOPPING
    
    # Cancel all running tasks
    for job_name, task in _scheduler_tasks.items():
        if not task.done():
            logger.info(f"Cancelling job {job_name}")
            task.cancel()
    
    # Wait for all tasks to complete or be cancelled
    pending_tasks = [task for task in _scheduler_tasks.values() if not task.done()]
    if pending_tasks:
        logger.info(f"Waiting for {len(pending_tasks)} tasks to finish")
        await asyncio.gather(*pending_tasks, return_exceptions=True)
    
    _scheduler_status = SchedulerStatus.STOPPED
    _scheduler_health["status"] = SchedulerStatus.STOPPED
    logger.info("Drift detection scheduler stopped")


def get_scheduler_health() -> Dict[str, Any]:
    """
    Get health information about the scheduler.
    
    Returns:
        Dictionary with scheduler health metrics
    """
    global _scheduler_health, _job_stats
    
    # Calculate uptime if the scheduler has been started
    if _scheduler_health["start_time"]:
        uptime_seconds = (datetime.utcnow() - _scheduler_health["start_time"]).total_seconds()
        _scheduler_health["uptime"] = uptime_seconds
    
    # Combine scheduler status with job stats
    health_info = {
        **_scheduler_health,
        "jobs": {
            "total": len(_scheduler_tasks),
            "running": sum(1 for t in _scheduler_tasks.values() if not t.done()),
            "stats": _job_stats,
            "recent_history": _job_history[-10:],  # Last 10 job runs
        }
    }
    
    return health_info

