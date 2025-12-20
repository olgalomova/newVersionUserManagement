FROM alpine:3.18

WORKDIR /app

RUN apk add --no-cache nodejs npm sqlite sqlite-dev bash

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/data /app/uploads

EXPOSE 3000

CMD ["node", "server.js"]
