from scanners.router import router as scanners_router
from fastapi import FastAPI

app = FastAPI(title="CloudCheck API", version="1.0.0", )

app.include_router(scanners_router, prefix="/api", tags=["scanners"])

@app.get("/api/health")
def health():
    """No auth. Use this to confirm the API is up."""
    return {"status": "ok"}