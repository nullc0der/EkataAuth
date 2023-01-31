FROM python:3.6-alpine
LABEL maintainer Prasanta Kakati <prasantakakati@ekata.social>
RUN apk update
RUN apk add build-base linux-headers postgresql-client \
    postgresql-dev libpq python3 python3-dev curl py3-pip libffi-dev \
    gcc musl-dev openssl-dev cargo
RUN ln -s /usr/bin/python3 /usr/bin/python
# RUN ln -s /usr/bin/pip3 /usr/bin/pip
ENV POETRY_HOME=/opt/poetry
ENV PATH="$POETRY_HOME/bin:$PATH"
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN mkdir /ekataauth
WORKDIR /ekataauth
COPY pyproject.toml poetry.lock /ekataauth/
RUN poetry config virtualenvs.create false && \
    poetry install --only=main --no-root
COPY . /ekataauth
