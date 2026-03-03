FROM node:20-alpine

# Use backend repo as build context; place it under /app/backend to match runtime paths
WORKDIR /app

# Copy everything from backend context into /app/backend
COPY . ./backend

# Install deps inside backend folder
WORKDIR /app/backend
RUN npm ci --omit=dev

# Run from /app so process.cwd() is /app and allowlist.ts resolves /app/backend/scanner/allowlist.json
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

EXPOSE 8080

CMD ["npx", "tsx", "backend/server/index.ts"]
