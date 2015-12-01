dev:
	pip install wheel
	pip install nose
	pip install check-manifest
	pip install -r requirements.txt
	pip install --upgrade -e .

test:
	nosetests --verbosity=2 tests

upload: check
	python setup.py sdist upload
	python setup.py bdist_wheel upload

clean:
	python setup.py clean

dist: check
	python setup.py sdist

check:
	check-manifest
	python setup.py check
