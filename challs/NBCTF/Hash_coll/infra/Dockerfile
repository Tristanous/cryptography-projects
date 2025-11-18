FROM python:3.11-alpine

RUN apk add --no-cache socat

WORKDIR /app

COPY server.py .

RUN chmod +x server.py

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 ./server.py"]