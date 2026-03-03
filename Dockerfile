FROM node:20-alpine

# Keep project root at /app so backend paths resolve to /app/backend/...
WORKDIR /app

# Install dependencies for the backend package
COPY backend/package*.json backend/
COPY backend/tsconfig.json backend/
WORKDIR /app/backend
RUN npm ci --omit=dev

# Copy backend source (server + scanner + shared) including allowlist
WORKDIR /app
COPY backend/server backend/server
COPY backend/scanner backend/scanner
COPY backend/shared backend/shared

# Runtime from /app (not /app/backend) so process.cwd() stays /app
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

EXPOSE 8080

CMD ["npx", "tsx", "backend/server/index.ts"]
