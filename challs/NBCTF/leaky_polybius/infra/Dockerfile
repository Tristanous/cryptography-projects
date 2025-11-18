FROM python:3.14.0rc1-alpine3.22

COPY ../src/chall.py /app/chall.py

WORKDIR /app

RUN apk add --no-cache socat coreutils

EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,fork,reuseaddr", "EXEC:stdbuf -i0 -o0 -e0 python3 /app/chall.py"]