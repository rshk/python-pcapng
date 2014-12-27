## Standard makefile for Python tests

BASE_PACKAGE = pcapng

.PHONY: all upload

all: help

help:
	@echo "AVAILABLE TARGETS"
	@echo "----------------------------------------"
	@echo "pypi_upload - build source distribution and upload to pypi"
	@echo "pypi_register - register proejct on pypi"
	@echo
	@echo "install - install project in production mode"
	@echo "install_dev - install project in development mode"
	@echo
	@echo "check (or 'test') - run tests"
	@echo "setup_tests - install dependencies for tests"
	@echo
	@echo "docs - build documentation (HTML)"
	@echo "publish_docs - publish documentation to GitHub pages"

pypi_register:
	python setup.py register -r https://pypi.python.org/pypi

pypi_upload:
	python setup.py sdist upload -r https://pypi.python.org/pypi

install:
	python setup.py install

install_dev:
	python setup.py develop

check:
	py.test -vvv --pep8 --cov=$(BASE_PACKAGE) --cov-report=term-missing ./tests

test: check

setup_tests:
	pip install pytest pytest-pep8 pytest-cov

docs:
	$(MAKE) -C docs html

publish_docs: docs
	ghp-import -n -p ./docs/build/html
	@echo
	@echo "HTML output published on github-pages"
