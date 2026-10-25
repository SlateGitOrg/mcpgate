# mcpgate — one command gates everything: `make check`.
UV ?= uv
RUN := $(UV) run --frozen

.PHONY: help install fmt format-check lint typecheck test cov check demo demo-ollama bench clean

help:
	@echo "make install      sync the locked environment (.venv)"
	@echo "make check        format-check + lint + typecheck + tests with coverage gate"
	@echo "make demo         offline end-to-end demo (uses local Ollama if reachable, else a scripted agent)"
	@echo "make demo-ollama  same demo, but require the local Ollama model"
	@echo "make bench        gateway overhead, micro-benchmarks and the pin-mutation matrix"
	@echo "make fmt          apply ruff formatting and safe fixes"

install:
	$(UV) sync --frozen

fmt:
	$(RUN) ruff format src tests benchmarks
	$(RUN) ruff check --fix src tests benchmarks

format-check: install
	$(RUN) ruff format --check src tests benchmarks

lint: install
	$(RUN) ruff check src tests benchmarks

typecheck: install
	$(RUN) mypy

test: install
	$(RUN) pytest

cov: install
	$(RUN) pytest --cov --cov-report=term

check: format-check lint typecheck cov

demo: install
	$(RUN) python -u -m mcpgate.demo

demo-ollama: install
	$(RUN) python -u -m mcpgate.demo --require-ollama

bench: install
	$(RUN) python -u benchmarks/bench.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist
