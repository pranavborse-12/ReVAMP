from fastapi import APIRouter
from .authentication import router

# Re-export the router
__all__ = ["router"]
