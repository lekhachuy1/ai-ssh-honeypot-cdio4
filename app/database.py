from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base


class Database:
    def __init__(self, url: str):
        kwargs: dict = {"future": True}
        connect_args: dict = {}

        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            if ":memory:" in url:
                kwargs["poolclass"] = StaticPool

        self.engine = create_engine(url, connect_args=connect_args, **kwargs)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        db = self.session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
