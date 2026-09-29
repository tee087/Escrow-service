FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
COPY frontend/package.json frontend/package.json
RUN npm install
COPY frontend ./frontend
RUN npm run build -w @cl-service/frontend
FROM nginx:alpine
COPY --from=build /app/frontend/dist /usr/share/nginx/html
