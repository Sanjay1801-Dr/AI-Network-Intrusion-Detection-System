# ==============================================================================
# AI-Based Network Intrusion Detection System (NIDS) - Frontend Container
# Multi-stage build: compiles React/Vite assets and serves static bundles
# ==============================================================================

# Stage 1: Build production bundle
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Minimal runtime container serving production assets
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY vite.config.js ./

EXPOSE 5173

# Serve production assets via Vite preview
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173"]
