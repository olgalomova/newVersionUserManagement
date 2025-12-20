FROM alpine:3.18 AS builder

WORKDIR /app

RUN apk add --no-cache nodejs npm

COPY frontend/package*.json frontend/tsconfig.json ./
RUN npm install typescript --save-dev

COPY frontend/*.ts frontend/*.html ./
RUN npx tsc

FROM caddy:2-alpine

COPY caddy/Caddyfile /etc/caddy/Caddyfile

COPY --from=builder /app/*.js /usr/share/caddy/
COPY --from=builder /app/*.html /usr/share/caddy/

RUN mkdir -p /usr/share/caddy/uploads

COPY frontend/uploads/default.png /usr/share/caddy/uploads/

EXPOSE 80 443

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
