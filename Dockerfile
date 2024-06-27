FROM cgr.dev/chainguard/python:latest-dev as build

WORKDIR /app

RUN python -m venv venv
ENV PATH="/app/venv/bin:$PATH"
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

FROM cgr.dev/chainguard/python:latest

WORKDIR /app

COPY . .
COPY --from=build /app/venv /app/venv

USER root
ENV PYTHONBUFFERED=1
ENV PATH="/app/venv/bin:$PATH"

ENTRYPOINT ["python", "./respotter.py"]