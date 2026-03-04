FROM node:20-alpine

# Install Python runtime for sniper/orchestrator engines
RUN apk add --no-cache python3 py3-pip \
  && ln -sf python3 /usr/bin/python

# Use backend repo as build context; place it under /app/backend to match runtime paths
WORKDIR /app

# Copy everything from backend context into /app/backend
COPY . ./backend

# Install deps inside backend folder
WORKDIR /app/backend
RUN npm ci --omit=dev
# Install Python deps (core + scanner) inside a venv to satisfy PEP 668
RUN python3 -m venv /py \
  && . /py/bin/activate \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir -r scanner/requirements.txt

# Run from /app so process.cwd() is /app and allowlist.ts resolves /app/backend/scanner/allowlist.json
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1
ENV PYTHON_BIN=/py/bin/python

EXPOSE 8080

CMD ["npx", "tsx", "backend/server/index.ts"]
