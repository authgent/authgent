"""Endpoint routers — thin HTTP layer delegating to services."""

from fastapi import APIRouter

from authgent_server.endpoints.agents import router as agents_router
from authgent_server.endpoints.authorize import router as authorize_router
from authgent_server.endpoints.device import router as device_router
from authgent_server.endpoints.health import router as health_router
from authgent_server.endpoints.introspect import router as introspect_router
from authgent_server.endpoints.register import router as register_router
from authgent_server.endpoints.revoke import router as revoke_router
from authgent_server.endpoints.stepup import router as stepup_router
from authgent_server.endpoints.token import router as token_router
from authgent_server.endpoints.wellknown import router as wellknown_router

api_router = APIRouter()
api_router.include_router(token_router)
api_router.include_router(authorize_router)
api_router.include_router(register_router)
api_router.include_router(revoke_router)
api_router.include_router(introspect_router)
api_router.include_router(device_router)
api_router.include_router(stepup_router)
api_router.include_router(agents_router)
api_router.include_router(wellknown_router)
api_router.include_router(health_router)
