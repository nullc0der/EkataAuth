FROM python:3.7
LABEL maintainer Prasanta Kakati <prasantakakati@ekata.social>
# TODO: Needs to check dependency thoroughly
RUN apt-get update && \
    apt-get install --yes build-essential postgresql-client \
    libpq-dev libjpeg-dev zlib1g-dev libffi-dev curl \
    musl-dev libffi-dev libssl-dev poppler-utils libmagic1
ENV POETRY_HOME=/opt/poetry
ENV PATH="$POETRY_HOME/bin:$PATH"
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN mkdir /ekataauth
WORKDIR /ekataauth
COPY pyproject.toml poetry.lock /ekataauth/
RUN poetry config virtualenvs.create false && \
    poetry install --only=main --no-root
COPY . /ekataauth
