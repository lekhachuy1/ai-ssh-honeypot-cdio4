.PHONY: install run test lint docker-up docker-down seed

install:
	python -m pip install -e ".[dev]"

run:
	python -m app.main

test:
	pytest

lint:
	ruff check .

docker-up:
	docker compose up --build

docker-down:
	docker compose down

seed:
	python scripts/seed_demo.py
