PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PIP := $(BIN)/pip
PYTEST := $(BIN)/pytest
RUFF := $(BIN)/ruff
WRX := $(BIN)/wrx
JUICE_URL ?= http://localhost:3000
TARGET ?= juice-shop
EXPORT_FORMAT ?= markdown

.PHONY: venv install test lint demo first-time juice-shop-up flow flow-scan gui
.PHONY: export

venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv
	$(PIP) install -e '.[dev]'

test:
	$(PYTEST) -q

lint:
	$(RUFF) check .

demo:
ifeq ($(DEMO),1)
	$(MAKE) juice-shop-up
	$(WRX) doctor --strict
	$(WRX) demo juice-shop --no-open
else
	$(WRX) doctor
	$(WRX) demo juice-shop --dry-run --no-open
endif

first-time: juice-shop-up
	$(WRX) doctor --strict
	$(WRX) demo juice-shop --no-open

juice-shop-up:
	@curl -fsS $(JUICE_URL) >/dev/null 2>&1 || docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

flow: juice-shop-up
ifeq ($(FLOW_DRY),1)
	$(WRX) flow juice-shop --dry-run --no-open
else
	$(WRX) flow juice-shop --no-open
endif

flow-scan: juice-shop-up
	$(WRX) flow juice-shop --with-scan --no-open

gui:
	$(WRX) gui --target juice-shop

export:
	$(WRX) export $(TARGET) --format $(EXPORT_FORMAT)
