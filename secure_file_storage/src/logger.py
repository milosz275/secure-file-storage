from loguru import logger
import os

log_path = "logs"
os.makedirs(log_path, exist_ok=True)
logger.add(os.path.join(log_path, "audit.log"), rotation="1 MB", level="INFO")
