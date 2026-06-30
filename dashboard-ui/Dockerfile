FROM nginx:alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY soc-dashboard-prototype.html /usr/share/nginx/html/index.html

EXPOSE 8502

CMD ["nginx", "-g", "daemon off;"]
