FROM python:3.13-slim AS dev

###### Create the standard user (name=user, home=/home/user)
RUN set -eux; \
    addgroup --gid 1000 user; \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos "" user;
USER 1000:1000

WORKDIR /app

# Add pip packages installed via user-mode (pip install --user ...) to PATH.
ENV PATH="$PATH:/home/user/.local/bin"

# Add ~/.venv to PATH. We do not use venv created by Poetry because it often
# struggles to find which venv to use or to find the one that it created.
# Instead, we are creating it ourselves and telling Poetry to use it.
#ENV POETRY_VIRTUALENVS_CREATE=false
ENV VENV_PATH=/app/.venv
ENV PATH="$VENV_PATH/bin:$PATH"

###### Install dependencies
RUN pip install --user "poetry~=1.8.1"
RUN python3 -m venv "$VENV_PATH"

# README needs to be copied for 'poetry install' to work)
COPY --chown=1000:1000 ./pyproject.toml ./poetry.lock ./README.rst /app/

# The project needs to be copied before running 'poetry install', otherwise
# it will refuse to install the dependencies.
COPY --chown=1000:1000 ./requests_hardened/ /app/requests_hardened/
RUN --mount=type=cache,mode=0755,uid=1000,gid=1000,target=/app/.cache/pypoetry \
    set -eux; \
    `# 'mkdir' is a workaround for https://github.com/python-poetry/poetry/issues/1573#issuecomment-555480711` \
    mkdir -p "$HOME/.cache/pypoetry/virtualenvs/"; \
    poetry env use "$VENV_PATH/bin/python3"; \
    poetry install --with dev

###### Copy remaining source code
COPY --chown=1000:1000 ./tests/ /app/tests

CMD ["bash", "-i"]
