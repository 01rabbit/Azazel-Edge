FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /etc/opencanaryd /var/log/opencanary

EXPOSE 22 80

CMD ["opencanaryd", "--dev"]
