import logging

import uvicorn

from app.config import get_settings
from app.web import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

settings = get_settings()
app = create_app(settings)


if __name__ == "__main__":
    uvicorn.run(app, host=settings.web_host, port=settings.web_port)
