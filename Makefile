.PHONY: help install run test lint format check up down test-container

help:
	@echo "install        installe les dependances de developpement"
	@echo "run            lance l'application sur http://localhost:8000"
	@echo "test           lance la suite de tests"
	@echo "lint           verifie le style du code"
	@echo "format         reformate le code"
	@echo "check          lint + tests, exactement ce que fait la CI"
	@echo "up / down      demarre ou arrete la pile Docker"

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

run:
	.venv/bin/uvicorn app.main:app --reload

test:
	.venv/bin/pytest

lint:
	.venv/bin/ruff check .

format:
	.venv/bin/ruff check --fix .

check: lint test

up:
	docker compose up -d

down:
	docker compose down

test-container:
	docker compose run --rm test
