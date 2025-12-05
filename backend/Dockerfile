FROM node:18-alpine

WORKDIR /app

# Копируем package.json и package-lock.json
COPY package*.json ./

# Устанавливаем зависимости
RUN npm install --omit=dev

# Копируем остальные файлы
COPY . .

# Создаём директорию для uploads
RUN mkdir -p /app/uploads

# Открываем порт
EXPOSE 3000

# Запускаем сервер
CMD ["node", "server.js"]
