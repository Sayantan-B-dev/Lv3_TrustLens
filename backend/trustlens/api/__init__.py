"""Versioned API router."""

from fastapi import APIRouter

from . import auth, automation, investigations, reports, system

api_router = APIRouter()
api_router.include_router(investigations.router)
api_router.include_router(automation.router)
api_router.include_router(reports.router)
api_router.include_router(auth.router)
api_router.include_router(system.router)

__all__ = ["api_router"]
