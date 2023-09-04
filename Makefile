lock-all:
	pip-compile -o requirements.txt pyproject.toml
	pip-compile --extra dev -o requirements_dev.txt pyproject.toml
