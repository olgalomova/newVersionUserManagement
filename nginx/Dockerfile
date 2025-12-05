# Используем официальный образ Nginx
FROM nginx:stable-alpine

# Создаём директорию для сертификатов
RUN mkdir -p /etc/nginx/cert

# Копируем конфигурацию nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Копируем SSL-сертификаты
COPY cert/olomova.42.fr.crt /etc/nginx/cert/olomova.42.fr.crt
COPY cert/olomova.42.fr.key /etc/nginx/cert/olomova.42.fr.key

# Копируем статику и uploads
COPY html/ /usr/share/nginx/html/
COPY html/uploads/ /usr/share/nginx/html/uploads/

# Открываем порты
EXPOSE 80 443

# Запускаем Nginx
CMD ["nginx", "-g", "daemon off;"]
