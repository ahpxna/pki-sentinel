FROM python:3.14.7-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/python3.14/site-packages/pip \
    /usr/local/lib/python3.14/site-packages/pip-*.dist-info
COPY server.py /server.py
# hadolint ignore=DL3066
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
