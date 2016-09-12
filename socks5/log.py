import logging
from kaviar import EventKvLoggerAdapter

logging.basicConfig(level=logging.DEBUG)
logger = EventKvLoggerAdapter.get_logger(__name__)

