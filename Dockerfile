FROM nginx:stable-alpine

# Serve prebuilt static files from `frontend/build`.
# This avoids running the React build inside Docker (which had dependency/lockfile issues).
COPY build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Ensure nginx has correct ownership for runtime
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx || true

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
