FROM python:3.10-alpine

LABEL maintainer="robert.ming@aio.so.ch"

WORKDIR /app

RUN apk add --no-cache git
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN pip3 install git+https://github.com/romics22/harbor2-python-client

COPY src/ .

CMD python3 vreport.py