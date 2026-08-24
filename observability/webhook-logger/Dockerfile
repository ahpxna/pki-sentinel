FROM python:3.14.7-alpine3.23@sha256:6b8f06d04d5305c1d1288435388df9165ab41e681fae6439d6349d8053cc3f83
COPY server.py /server.py
# hadolint ignore=DL3066
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
