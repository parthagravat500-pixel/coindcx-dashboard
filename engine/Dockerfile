FROM node:22-bookworm-slim
WORKDIR /app
COPY lib ./lib
COPY engine ./engine
ENV PORT=10000 DATA_DIR=/var/data
EXPOSE 10000
VOLUME ["/var/data"]
CMD ["node","--experimental-strip-types","engine/server.mjs"]
