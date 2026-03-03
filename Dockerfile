FROM node:20-alpine

# Keep backend under /app/backend so server paths resolve (e.g., backend/scanner/allowlist.json)
WORKDIR /app/backend

# Install dependencies for the backend package
COPY package*.json ./
COPY tsconfig.json ./
RUN npm ci --omit=dev

# Copy backend source (server + scanner + shared)
COPY server ./server
COPY scanner ./scanner
COPY shared ./shared

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

EXPOSE 8080

CMD ["npx", "tsx", "server/index.ts"]
