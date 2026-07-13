.PHONY: install format lint test benchmark demo docker clean

install:
	uv sync --frozen --all-extras

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv lock --check
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src

test:
	uv run pytest --cov=identity_attack_graph --cov-report=term-missing --cov-report=xml

benchmark:
	uv run identity-graph benchmark --iterations 100

demo:
	uv run identity-graph serve --host 127.0.0.1 --port 8080

docker:
	docker compose up --build

clean:
	rm -rf .coverage coverage.xml reports/*.json reports/*.csv reports/*.md reports/*.dot
