# syntax=docker/dockerfile:1

FROM node:20-slim AS base
WORKDIR /app
ENV NODE_ENV=production

# Build stage
FROM base AS build

# Install build dependencies
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
    python3 \
    make \
    g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./
COPY adapter/package*.json ./adapter/

# Install all dependencies (including dev for build)
RUN npm install --include=dev
RUN cd adapter && npm install --include=dev

# Copy source code
COPY adapter/ ./adapter/

# Build TypeScript
RUN cd adapter && npm run build

# Prune dev dependencies
RUN cd adapter && npm prune --production

# Production stage
FROM base

# Install runtime dependencies only
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
    curl \
    ca-certificates \
    tini && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

WORKDIR /app/adapter

# Copy built application
COPY --from=build --chown=app:app /app/adapter/dist ./dist
COPY --from=build --chown=app:app /app/adapter/node_modules ./node_modules
COPY --from=build --chown=app:app /app/adapter/package.json ./

# Copy compiled circuits (needed for proof generation)
COPY --chown=app:app circuits/transfer/target/transfer.json /app/circuits/transfer/target/
COPY --chown=app:app circuits/withdraw/target/withdraw.json /app/circuits/withdraw/target/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT:-8546} -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' || exit 1

EXPOSE 8546

ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/index.js"]
