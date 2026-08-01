FROM python:3.12.4-alpine3.20
COPY server.py /server.py
USER nobody
EXPOSE 9099
ENTRYPOINT ["python3", "/server.py", "9099"]
