FROM node:20-alpine AS build

WORKDIR /app

# Install deps for full app (frontend + backend)
COPY package*.json ./
COPY tsconfig.json vite.config.ts tailwind.config.ts postcss.config.js drizzle.config.ts ./ || true
COPY script script
COPY client client
COPY backend backend
COPY shared shared

RUN npm ci

# Build client + server bundle
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV FORCE_STATIC=1

# Copy built artifacts and runtime deps
COPY --from=build /app/dist ./dist
COPY --from=build /app/package*.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/backend/scanner ./backend/scanner

EXPOSE 8080

CMD ["node", "dist/index.cjs"]
