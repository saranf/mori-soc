FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY src ./src
COPY schema ./schema
COPY scripts ./scripts

# 한글 폰트 (PDF 증적 리포트 렌더링용 — fonts-nanum NanumGothic)
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-nanum \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        fastapi==0.115.12 \
        uvicorn==0.34.0 \
        psycopg[binary]==3.2.6 \
        ldap3==2.9.1 \
        httpx==0.28.1 \
        reportlab==4.2.5

EXPOSE 8000

CMD ["uvicorn", "mori_soc.api.server:create_app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000"]