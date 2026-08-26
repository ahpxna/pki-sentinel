FROM python:3.14.7-alpine3.24@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/python3.14/site-packages/pip \
    /usr/local/lib/python3.14/site-packages/pip-*.dist-info
COPY server.py /server.py
# hadolint ignore=DL3066
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
