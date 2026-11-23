FROM python:3.15.2-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/python3.14/site-packages/pip \
    /usr/local/lib/python3.14/site-packages/pip-*.dist-info
COPY server.py /server.py
# hadolint ignore=DL3066
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
