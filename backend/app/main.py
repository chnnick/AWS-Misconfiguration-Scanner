from contextlib import asynccontextmanager

from fastapi import FastAPI
from scanners.router import router as scanners_router

from app.config import require_aws_env

# Lifespan management, makes sure the AWS environment + Keys are loaded before the app starts
@asynccontextmanager
async def lifespan(app: FastAPI):
    require_aws_env()
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