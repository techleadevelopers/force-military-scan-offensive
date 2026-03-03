FROM node:20-alpine AS build
WORKDIR /app

# Copiar apenas os arquivos do backend
COPY package*.json ./
COPY tsconfig.json ./

# Se houver dependências compartilhadas, ajuste conforme necessário
# COPY ../shared ./shared  # Se shared estiver fora do diretório backend

RUN npm ci

# Copiar o código do backend
COPY . .

# Se tiver um build específico para backend
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080

COPY --from=build /app/dist ./dist
COPY --from=build /app/package*.json ./
COPY --from=build /app/node_modules ./node_modules

EXPOSE 8080

CMD ["node", "dist/index.cjs"]