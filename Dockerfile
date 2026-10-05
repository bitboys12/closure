# CLOSURE: Effect-Bound Approval Firewall Sandbox Environment
FROM node:20-bookworm-slim

# Install system utilities, strace for tracing, and python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    python3 \
    python3-pip \
    python3-venv \
    procps \
    curl \
    net-tools \
    iproute2 \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python gateway & test dependencies
RUN pip3 install --no-cache-dir --break-system-packages \
    fastapi \
    uvicorn \
    pydantic \
    websockets \
    pytest \
    pytest-asyncio \
    httpx

# Set up work directory
WORKDIR /workspace

ENV NODE_ENV=development
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python3", "-m", "uvicorn", "core.gateway:app", "--host", "0.0.0.0", "--port", "8000"]
