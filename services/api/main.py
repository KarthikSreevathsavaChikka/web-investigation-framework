from fastapi import FastAPI

from services.api.routers import health, investigations, jobs

app = FastAPI(
    title="Web Investigation Framework API",
    version="0.1.0",
    description="Versioned service boundary for Dynamic Investigation and passive OSINT data.",
)
app.include_router(health.router)
app.include_router(investigations.router)
app.include_router(jobs.router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"service": "web-investigation-api", "docs": "/docs", "health": "/health/ready"}
