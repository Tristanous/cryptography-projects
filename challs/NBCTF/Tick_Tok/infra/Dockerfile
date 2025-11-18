FROM python:3.11-alpine

RUN apk add --no-cache socat coreutils


RUN adduser -D -h /app appuser
WORKDIR /app

COPY server.py /app/server.py
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,fork,reuseaddr", "EXEC:stdbuf -i0 -o0 -e0 python3 /app/server.py"]
