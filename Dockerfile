FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY src ./src
COPY schema ./schema

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        fastapi==0.115.12 \
        uvicorn==0.34.0 \
        psycopg[binary]==3.2.6

EXPOSE 8000

CMD ["uvicorn", "mori_soc.api.server:create_app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000"]