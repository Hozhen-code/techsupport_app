FROM python:3.11-slim

# 시스템 라이브러리(WeasyPrint용)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi8 \
    libxml2 \
    libxslt1.1 \
    fonts-noto-cjk \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# 코드 복사 (개발 중엔 볼륨이 덮어씌움)
COPY . /app

# uvicorn으로 고정 실행 (reload X)
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
