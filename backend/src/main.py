import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router
from src.config import settings

# --- Logging setup ---
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phishing_detector")

app = FastAPI(title="Phishing Email Detector", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    logger.info(">>> %s %s", request.method, request.url.path)
    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    logger.info("<<< %s %s — %d (%.1fms)", request.method, request.url.path, response.status_code, duration_ms)
    return response


@app.on_event("startup")
def on_startup():
    logger.info("Phishing Email Detector starting up")
    logger.info("Debug mode: %s", settings.debug)


@app.get("/health")
def health():
    return {"status": "ok"}
