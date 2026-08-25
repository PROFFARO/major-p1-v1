"""
FastAPI Server Entry Point and Uvicorn Background Runner.
"""

import logging
import threading
import time
from typing import Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ml_engine.config import REST_API_HOST, REST_API_PORT
from ml_engine.api.routes import router as api_router, set_api_dependencies
from ml_engine.storage import DatabaseManager
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot

logger = logging.getLogger("ml_engine.api.server")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="eBPF-ML Security Engine & LLM Copilot API",
        description="High-Performance REST Services & Analytical Query API for eBPF SOC Dashboard",
        version="1.0.0",
    )

    # Enable CORS for React Security Dashboard frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    return app


app = create_app()


class APIServerRunner:
    """Helper to run Uvicorn server in a non-blocking background daemon thread."""

    def __init__(
        self,
        host: str = REST_API_HOST,
        port: int = REST_API_PORT,
        db_mgr: Optional[DatabaseManager] = None,
        copilot: Optional[LLMSecurityCopilot] = None,
        engine=None,
        mitigator=None,
    ):
        self.host = host
        self.port = port
        self.db_mgr = db_mgr or DatabaseManager()
        self.copilot = copilot or LLMSecurityCopilot()
        self.engine = engine
        self.mitigator = mitigator

        set_api_dependencies(
            db_mgr=self.db_mgr,
            copilot=self.copilot,
            engine=self.engine,
            mitigator=self.mitigator,
        )

        self._server = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start Uvicorn server in background thread."""
        config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False,
        )
        self._server = uvicorn.Server(config)

        self._thread = threading.Thread(
            target=self._server.run,
            daemon=True,
            name="fastapi-rest-server",
        )
        self._thread.start()
        logger.info("FastAPI REST Server listening on http://%s:%d/api/v1/health", self.host, self.port)

    def stop(self):
        """Stop Uvicorn server."""
        if self._server:
            self._server.should_exit = True
            if self._thread and self._thread.is_alive():
                try:
                    self._thread.join(timeout=0.2)
                except Exception:
                    pass
            logger.info("FastAPI REST Server stopped")
