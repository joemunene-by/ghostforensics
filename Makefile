.PHONY: install dev test lint format clean build

install:
	pip install -e .

dev:
	pip install -e ".[dev,all]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=ghostforensics --cov-report=term-missing

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

build:
	python -m build

analyze-sample:
	ghostforensics analyze examples/sample_dump.json --output report.html
