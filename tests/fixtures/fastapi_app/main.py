from fastapi import FastAPI

from .routes import router as library_router

app = FastAPI()
app.include_router(library_router, prefix="/v1")
