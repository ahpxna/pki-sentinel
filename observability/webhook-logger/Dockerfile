FROM python:3.14.8-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/python3.14/site-packages/pip \
    /usr/local/lib/python3.14/site-packages/pip-*.dist-info
COPY server.py /server.py
# hadolint ignore=DL3066
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
