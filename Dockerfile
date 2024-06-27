### Builder image
FROM ubuntu:latest AS deps

# install python
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y python3.12 python3.12-dev python3.12-venv python3-pip python3-wheel build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# create and activate virtual environment
RUN python3.12 -m venv /root/venv
ENV PATH="/root/venv/bin:$PATH"

# install requirements
COPY requirements.txt .
RUN pip install -r requirements.txt

### Runner image
FROM ubuntu:latest AS runner-image

# install python
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y python3.11 python3-venv && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# setup app directory
RUN mkdir -p /run
WORKDIR /run
COPY . .
COPY --from=deps /root/venv /root/venv

# prepare runtime environment
USER root
ENV VIRTUAL_ENV=/root/venv
ENV PATH="/root/venv/bin:$PATH"
ENV PYTHONBUFFERED=1

ENTRYPOINT ["python", "./respotter.py"]