FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src ./src
COPY public ./public
COPY server.js ./

FROM node:20-alpine AS runtime

RUN apk add --no-cache \
    curl \
    tini \
    && addgroup -g 1001 -S nodejs \
    && adduser -u 1001 -S nodejs -G nodejs

WORKDIR /app

COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
COPY --from=builder --chown=nodejs:nodejs /app/public ./public
COPY --from=builder --chown=nodejs:nodejs /app/server.js ./

RUN mkdir -p logs data && chown -R nodejs:nodejs logs data

USER nodejs

ENV NODE_ENV=production \
    PORT=3001 \
    LOG_LEVEL=info

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
