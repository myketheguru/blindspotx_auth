
# Development Environment Setup Guide (FastAPI)

This guide provides instructions for setting up your development environment for the FastAPI-based backend project.

---

## Prerequisites

* Python 3.10 or later
* `pip` and `virtualenv`
* Git
* SQLite (or your target database system)
* A code editor (VS Code recommended)

---

## Getting Started

### 1. **Clone the repository**

```bash
git clone https://github.com/your-username/your-project.git
cd your-project
```

### 2. **Set up a virtual environment**

#### Using `venv`

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. **Install dependencies**

Using `pip`:

```bash
pip install -r requirements.txt
```

### 4. **Set up environment variables**

Create a `.env` file in the root directory:

```env
DEBUG=true
DATABASE_URL=sqlite:///./blindspotx.db
SECRET_KEY=your_secret_key
```

Refer to `.env.example` for all expected variables.

### 5. **Apply database migrations**

```bash
alembic upgrade head
```

### 6. **Run the development server**

```bash
uvicorn app.main:app --reload
```

Visit: [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive API docs.

---

## Development Workflow

### 🧪 Running tests

```bash
pytest
```

> Consider using a pre-commit hook for consistent code style.

### 🛠 Rebuilding the database (development only)

```bash
python setup_main_db.py
```

### 🐳 Using Docker (Optional)

To spin up services using Docker:

```bash
docker-compose up --build
```

---

## Useful Commands

| Task                     | Command                                                           |
| ------------------------ | ------------------------------------------------------------------|
| Run app                  | `uvicorn app.main:app --reload` or `python run.py` (Recommended)  |
| Run tests                | `pytest`                                                          |
| Apply Alembic migrations | `alembic upgrade head`                                            |
| Create Alembic migration | `alembic revision --autogenerate -m "Message"`                    |

---

## Troubleshooting

* ✅ Ensure Python, pip, and required tools are installed correctly.
* ✅ Double-check `.env` values and database URLs.
* 🧹 Clean virtual environments and re-install if necessary.
* 🧪 Use `--log-level debug` with `uvicorn` for more verbose output.
* ❓ Still stuck? Open an issue or contact a maintainer.

---
