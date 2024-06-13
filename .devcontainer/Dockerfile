FROM mcr.microsoft.com/devcontainers/python:3

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install git

COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt