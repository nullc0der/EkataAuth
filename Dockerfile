FROM python:3.6-alpine
LABEL maintainer Prasanta Kakati <prasantakakati@ekata.social>
RUN apk update
RUN apk add build-base linux-headers postgresql-client \
    postgresql-dev libpq python3 python3-dev curl py3-pip libffi-dev \
    gcc musl-dev openssl-dev cargo
RUN ln -s /usr/bin/python3 /usr/bin/python
# RUN ln -s /usr/bin/pip3 /usr/bin/pip
RUN curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python
RUN mkdir /ekataauth
WORKDIR /ekataauth
COPY pyproject.toml poetry.lock /ekataauth/
RUN source $HOME/.poetry/env && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev
COPY . /ekataauth
