help:
	@echo "  dev         create a development environment using virtualenv"
	@echo "  clean       remove unwanted stuff"
	@echo "  lint        check style with flake8"
	@echo "  test        run tests"
	@echo "  build       generate source and wheel dist files"
	@echo "  upload      generate source and wheel dist files and upload them"

venv:
ifndef VIRTUAL_ENV
	$(error Please install and activate a virtualenv before using the init or dev targets)
endif

init: venv
	pip install wheel
	pip install nose
	pip install check-manifest
	pip install -r requirements.txt

dev: init
	pip install --upgrade -e .

lint:
	@rm violations.flake8.txt
	flake8 kenkou > violations.flake8.txt

test:
	nosetests --verbosity=2 tests

upload: check
	python setup.py sdist upload
	python setup.py bdist_wheel upload

clean:
	python setup.py clean

build: check
	python setup.py sdist

check: test lint
	check-manifest
	python setup.py check
