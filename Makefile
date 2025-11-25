.PHONY: format check test all badges coverage

PROJECT_FILES := $(shell find rfc3230_digest_headers/ tests/ -name '*.py')

all: format check

format:
	uv run ruff format

check:
	uv run ruff check --fix

test:
	uv run pytest -v tests/

build:
	uv build

clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info
	rm -f .coverage

.coverage: $(PROJECT_FILES)
	uv run --with coverage coverage run --source rfc3230_digest_headers/ -m pytest -v tests/
	uv run --with coverage coverage report -m

coverage: .coverage

badges/python-versions.svg:
	mkdir -p badges
	uv run --with pybadges --with setuptools -m pybadges --left-text Python --right-color blue --right-text '3.10 | 3.11 | 3.12 | 3.13 | 3.14'  > badges/python-versions.svg

badges/coverage.svg: coverage
	mkdir -p badges
	uv run --with pybadges --with setuptools -m pybadges --left-text Coverage --right-color green --right-text "$$(uv run --with coverage coverage json --pretty-print -o - | jq '.totals.percent_covered_display' | tr -d '"%')%" > badges/coverage.svg

badges: badges/python-versions.svg badges/coverage.svg