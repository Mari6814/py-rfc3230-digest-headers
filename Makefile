.PHONY: test lint format

test:
	uv run -m coverage run --source=rfc3230_digest_headers -m pytest tests/
	uv run -m coverage report -m

lint:
	uv run -m ruff check --fix rfc3230_digest_headers/* tests/*

format:
	uv run -m ruff format rfc3230_digest_headers/* tests/*
