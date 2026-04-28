FROM python:3.12-slim-bookworm

# ── system deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        wget \
        unzip \
        git \
    && rm -rf /var/lib/apt/lists/*

# ── JADX ──────────────────────────────────────────────────────────────────────
ARG JADX_VERSION=1.5.0
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# ── APKLeaks ──────────────────────────────────────────────────────────────────
RUN pip install --no-cache-dir apkleaks

# ── Python deps ───────────────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── App ───────────────────────────────────────────────────────────────────────
COPY analyze.py tools.py filter.py analyst.py report.py ./

# Volumes: /data/input (APK), /data/output (reports)
RUN mkdir -p /data/input /data/output

ENTRYPOINT ["python", "analyze.py"]
CMD ["--help"]
