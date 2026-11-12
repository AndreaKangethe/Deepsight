import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import Base, engine, ensure_columns
from .routers import assets, auth, findings, intel, ml, scanning
from .services import scheduler

log = logging.getLogger("asivm")
STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    for attempt in range(30):
        try:
            Base.metadata.create_all(engine)
            ensure_columns()
            break
        except Exception as e:  # database still starting
            log.warning("database not ready (%s), retrying", e)
            time.sleep(2)
    else:
        raise RuntimeError("database unavailable")
    if settings.secret_key == "change-me-in-production":
        log.warning("ASIVM_SECRET_KEY is the default value: set a strong secret before real use")
    scheduler.start()
    yield
    scheduler.stop()


app = FastAPI(title="ASIVM", version="1.0.0",
              description="Asset Security Intelligence and Visibility Management", lifespan=lifespan)
for r in (auth.router, assets.router, scanning.router, findings.router, intel.router, ml.router):
    app.include_router(r)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")
