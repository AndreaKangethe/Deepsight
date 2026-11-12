from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_columns():
    """Additive schema upgrade: add any nullable column the models have but the database lacks."""
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    with engine.begin() as c:
        for t in Base.metadata.sorted_tables:
            if not insp.has_table(t.name):
                continue
            have = {x["name"] for x in insp.get_columns(t.name)}
            for col in t.columns:
                if col.name not in have:
                    ddl = col.type.compile(dialect=engine.dialect)
                    c.execute(text(f'ALTER TABLE "{t.name}" ADD COLUMN "{col.name}" {ddl}'))
