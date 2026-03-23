import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from scanner.router import router as scanners_router

log = logging.getLogger("uvicorn.error")

@asynccontextmanager
async def lifespan(app: FastAPI):
    port = os.environ.get("PORT", "8000")
    host = os.environ.get("API_HOST", "127.0.0.1")
    base = f"http://{host}:{port}"
    log.info(
        "\nCloudCheck API — %s\ndocs: %s/docs\nhealth: %s/api/health\nscanners:\n\tPOST %s/api/scanner/ec2\n\tPOST %s/api/scanner/s3\n\tPOST %s/api/scanner/lambda\n\tPOST %s/api/scanner/iam",
        base,
        base,
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

app.include_router(scanners_router, prefix="/api", tags=["scanner"])

@app.get("/api/health")
def health():
    """No auth. Use this to confirm the API is up."""
    return {"status": "ok"}