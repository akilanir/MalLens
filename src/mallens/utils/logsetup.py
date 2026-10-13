import sys
from loguru import logger
from pathlib import Path


def setup_logging(level: str = "INFO", androguard_level: str = "ERROR", log_file: str | None = None) -> None:
    """Androguard 4.x logs through loguru's global logger and is extremely
    verbose. We reset it and apply a level filter that throttles anything
    from androguard modules separately from our own messages."""
    logger.remove()

    def _filter(record):
        mod = record["name"] or ""
        if mod.startswith("androguard"):
            return record["level"].no >= logger.level(androguard_level).no
        return record["level"].no >= logger.level(level).no

    logger.add(
        sys.stderr,
        filter=_filter,
        level=0,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | "
               "<cyan>{name}</cyan> - {message}",
    )

    # File
    if log_file:
        Path(log_file).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        logger.add(
            log_file,
            filter=_filter,
            level=0,
            rotation="100 MB",
            retention="7 days",
            compression="zip",
            enqueue=True,
            backtrace=True,
            diagnose=False,
            format=(
                "{time:YYYY-MM-DD HH:mm:ss} | "
                "{level:<7} | "
                "{process.name} | "
                "{name}:{function}:{line} | "
                "{message}"
            ),
        )

