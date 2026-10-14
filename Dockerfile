FROM mcr.microsoft.com/playwright/python:v1.62.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends poppler-utils libreoffice-writer \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; p = sync_playwright().start(); assert Path(p.chromium.executable_path).is_file(), 'Playwright browser image and package versions must match'; p.stop()"

COPY . .
RUN mkdir -p /app/data /app/evidence /app/reports \
    && useradd --create-home --uid 10001 investigator \
    && chown -R investigator:investigator /app

USER investigator
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=3)"
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
