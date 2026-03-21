import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from scanners.router import router as scanners_router

from app.config import require_aws_env

log = logging.getLogger("uvicorn.error")

@asynccontextmanager
async def lifespan(app: FastAPI):
    require_aws_env()
    port = os.environ.get("PORT", "8000")
    host = os.environ.get("API_HOST", "127.0.0.1")
    base = f"http://{host}:{port}"
    log.info(
        "CloudCheck API — %s  |  docs: %s/docs  |  health: %s/api/health  |  scanners: POST %s/api/scanners/ec2, POST %s/api/scanners/s3",
        base,
        base,
        base,
        base,
        base,
    )
    yield


app = FastAPI(
    title="CloudCheck API",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(scanners_router, prefix="/api", tags=["scanners"])

@app.get("/api/health")
def health():
    """No auth. Use this to confirm the API is up."""
    return {"status": "ok"}