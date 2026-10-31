# breakAPI production image. No dependencies to install; the demo API and tests are not shipped.
FROM node:22-alpine

ENV NODE_ENV=production \
    BREAKAPI_ENV=production \
    BREAKAPI_DATA=/data \
    HOST=0.0.0.0 \
    PORT=7300

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 7300

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:7300/healthz >/dev/null || exit 1

CMD ["node", "src/main.js"]
