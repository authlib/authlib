.PHONY: tests clean clean-pyc clean-build docs build

build:
	@python3 -m build

clean: clean-build clean-pyc clean-docs clean-tox

tests:
	@TOXENV=py,flask,django,coverage tox

clean-build:
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg
	@rm -fr *.egg-info


clean-pyc:
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
	@find . -name '__pycache__' -exec rm -fr {} +

clean-docs:
	@rm -fr  docs/_build

clean-tox:
	@rm -rf .tox/

build-docs:
	@sphinx-build docs build/_html -a
