import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

from scanner.router import router as scanners_router

from .neo4j_client import neo4j_client

logger = logging.getLogger(__name__)

_cors_raw = os.environ.get(
    "CORS_ORIGINS",
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
)
_cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]

@asynccontextmanager
async def lifespan(app: FastAPI):
    port = os.environ.get("PORT", "8000")
    host = os.environ.get("API_HOST", "127.0.0.1")
    base = f"http://{host}:{port}"
    logger.info(
        "\nCloudSight API — %s\ndocs: %s/docs\nhealth: %s/api/health\nscanners:\n\tPOST %s/api/scanner/ec2\n\tPOST %s/api/scanner/s3\n\tPOST %s/api/scanner/lambda\n\tPOST %s/api/scanner/iam",
        base,
        base,
        base,
        base,
        base,
        base,
        base,
    )
    yield
    #Close Neo4j connection on shutdown
    neo4j_client.close()


app = FastAPI(
    title="CloudSight API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    try:
        response = await call_next(request)
        line = "%s %s -> %s"
        args = (request.method, request.url.path, response.status_code)
        if response.status_code >= 400:
            logger.warning(line, *args)
        else:
            logger.info(line, *args)
        return response
    except Exception:
        logger.exception("%s %s", request.method, request.url.path)
        raise


app.include_router(scanners_router, prefix="/api", tags=["scanner"])

@app.get("/api/health")
def health():
    """No auth. Use this to confirm the API is up."""
    return {"status": "ok"}

# Neo4j Data Endpoints

@app.get("/api/findings")
def get_findings(severity: str = None):
    # Get all security findings
    try:
        if severity:
            return neo4j_client.get_findings_by_severity(severity.upper())
        return neo4j_client.get_all_findings()
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/graph")
def get_graph(limit: int = 100):
    # Get graph visualization data
    try:
        return neo4j_client.get_graph_data(limit)
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/stats")
def get_statistics():
    # Get summary statistics
    try:
        return neo4j_client.get_statistics()
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/ec2")
def get_ec2_instances():
    # Get all EC2 instances with their findings
    try:
        return neo4j_client.get_ec2_instances()
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/s3")
def get_s3_buckets():
    # Get all S3 buckets with their findings
    try:
        return neo4j_client.get_s3_buckets()
    except Exception as e:
        return {"error": str(e)}