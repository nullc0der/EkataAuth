FROM alpine:latest
LABEL maintainer Prasanta Kakati <prasantakakati@ekata.social>
RUN apk update
RUN apk add build-base linux-headers postgresql-client postgresql-dev libpq python3 python3-dev
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN pip3 install pipenv
RUN mkdir /ekataauth
WORKDIR /ekataauth
COPY Pipfile /ekataauth
COPY Pipfile.lock /ekataauth
RUN pipenv install --system
COPY . /ekataauth
