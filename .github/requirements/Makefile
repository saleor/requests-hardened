lock-publish-pypi:
	pip-compile --generate-hashes -o poetry-requirements-hashes.txt poetry-requirements.in
	pip-compile -o poetry-requirements-no-hashes.txt poetry-requirements.in

lock-all: lock-publish-pypi
