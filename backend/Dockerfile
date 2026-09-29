FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
COPY backend/package.json backend/package.json
COPY shared/package.json shared/package.json
RUN npm install
COPY . .
RUN npx prisma generate --schema database/schema.prisma && npm run build -w @cl-service/backend
CMD ["node", "backend/dist/server.js"]
