FROM docker.io/library/python:3.14.5-alpine3.23@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614
COPY --chown=65532:65532 adapter.py /agentmemory/adapter
USER 65532:65532
ENTRYPOINT ["python3", "-I", "/agentmemory/adapter"]
