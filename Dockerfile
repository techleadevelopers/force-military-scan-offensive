FROM node:20-alpine

WORKDIR /app

# Install dependencies for the backend package (lockfile optional)
COPY package*.json tsconfig.json ./backend/
RUN cd backend && if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy backend sources (server + scanner + shared) keeping the expected layout
COPY . ./backend

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

EXPOSE 8080

# Use the backend package's binaries and keep process.cwd at /app
CMD ["npx", "--yes", "--prefix", "/app/backend", "tsx", "/app/backend/server/index.ts"]
