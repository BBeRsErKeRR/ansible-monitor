.DEFAULT_GOAL := help

.PHONY:
SHELL=/bin/bash
SHELLOPTS:=$(if $(SHELLOPTS),$(SHELLOPTS):)pipefail:errexit
DOCKER_BUILDKIT=1
PYPI_KEY=${BUILD_USER}:${ARTY_API_KEY}
PIP_NO_CACHE_DIR=off
PIPENV_CLEAR=on

FULL_IMAGE_NAME:=${TARGET_IMAGE_PATH}:${COMPONENT_VERSION}
export

.PHONY: help
help: ## Display this help
	@IFS=$$'\n'; for line in `grep -h -E '^[a-zA-Z_#-]+:?.*?## .*$$' $(MAKEFILE_LIST)`; do if [ "$${line:0:2}" = "##" ]; then \
	echo $$line | awk 'BEGIN {FS = "## "}; {printf "\n\033[33m%s\033[0m\n", $$2}'; else \
	echo $$line | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'; fi; \
	done; unset IFS;

.PHONY: build
depth:  ## Install dependencies
	poetry install
