FROM node:22-alpine as build
WORKDIR /app
COPY frontend/ /app/
RUN npm install && npm run build
FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
