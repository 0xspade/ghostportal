# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License
# Flask-Migrate / Alembic environment configuration

from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import the Flask app and models so Alembic can detect schema changes
from app import create_app
from app.extensions import db
import app.models  # noqa: F401 — ensure all models are registered in metadata

app = create_app()

# add your model's MetaData object here for 'autogenerate' support
with app.app_context():
    target_metadata = db.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Use the Flask app's database URL
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = app.config["SQLALCHEMY_DATABASE_URI"]

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
