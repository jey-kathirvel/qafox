"""Shared SQLAlchemy engine and declarative metadata."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str | None = None):
    return create_engine(
        database_url or get_settings().database_url,
        pool_pre_ping=True,
        pool_recycle=300,
    )


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
