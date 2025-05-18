# app/api/routes/drift_router.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.drift import DriftReport
from app.core.database import get_db

router = APIRouter(prefix="/drift", tags=["Drift Detection"])

@router.get("/reports", response_model=list[DriftReport])
async def get_drift_reports(db: AsyncSession = Depends(get_db)):
    """Get list of detected drift reports"""
    result = await db.execute(select(DriftReport))
    reports = result.scalars().all()
    return reports
