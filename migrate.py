import sys,os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import your Base from the project
from database import Base
from models import *  # Ensure all models are imported to include them in migrations
from alembic.config import Config

# Alembic Config object for settings
config = Config("alembic.ini")

# Logging setup
fileConfig(config.config_file_name)

# Set target metadata for autogeneration
target_metadata = Base.metadata

# Database connection
def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else None

    if command == "init":
        # Initialize Alembic (Run once to set up the initial structure)
        import os
        if not os.path.exists("alembic"):
            os.system("alembic init alembic")
        else:
            print("Alembic already initialized.")
    elif command == "migrate":
        # Generate a new migration
        message = sys.argv[2] if len(sys.argv) > 2 else "Auto migration"
        os.system(f"alembic revision --autogenerate -m \"{message}\"")
    elif command == "upgrade":
        # Apply migrations
        os.system("alembic upgrade head")
    elif command == "downgrade":
        # Rollback migrations (default to -1 step)
        step = sys.argv[2] if len(sys.argv) > 2 else "-1"
        os.system(f"alembic downgrade {step}")
    else:
        print("Usage: migrate.py [init|migrate|upgrade|downgrade]")
