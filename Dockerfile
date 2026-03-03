FROM node:20-alpine

WORKDIR /app

# Install dependencies for the backend package
COPY package*.json tsconfig.json ./backend/
RUN cd backend && npm ci --omit=dev

# Copy backend sources (server + scanner + shared) keeping the expected layout
COPY . ./backend

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

EXPOSE 8080

# Use the backend package's binaries and keep process.cwd at /app
CMD ["npx", "--yes", "--prefix", "/app/backend", "tsx", "/app/backend/server/index.ts"]
