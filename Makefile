CONTAINER_IMAGE_NAME := requests-hardened
DOCKER := docker

lock-all:
	pip-compile -o requirements.txt pyproject.toml
	pip-compile --extra dev -o requirements_dev.txt pyproject.toml

container-build:
	$(DOCKER) build --progress=plain -t "$(CONTAINER_IMAGE_NAME)" .

shell: container-build
	$(DOCKER) run --rm -ti \
		-v ./tests:/app/tests:ro \
		-v ./requests_hardened:/app/requests_hardened:ro \
		--name "$(CONTAINER_IMAGE_NAME)" \
		"$(CONTAINER_IMAGE_NAME)"
