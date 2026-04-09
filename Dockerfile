# ---- Stage 1: Build frontend (webpack) ----
FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci
COPY webpack.config.js ./
COPY src/ ./src/
RUN npm run build

# ---- Stage 2: Build Go backend ----
FROM golang:1.26-alpine AS go-build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o chat .

# ---- Stage 3: Build YouTube WebSocket service ----
FROM oven/bun:latest AS yt-build
WORKDIR /build
COPY youtube-websocket/package.json youtube-websocket/bun.lock ./
RUN bun install --frozen-lockfile
COPY youtube-websocket/src/ ./src/
COPY youtube-websocket/tsconfig.json ./

# ---- Stage 4: Final runtime image ----
FROM oven/bun:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Go binary
COPY --from=go-build /build/chat ./chat

# Copy built frontend
COPY --from=frontend-build /build/dist ./dist

# Copy YouTube WebSocket service
COPY --from=yt-build /build/node_modules ./youtube-websocket/node_modules
COPY --from=yt-build /build/src ./youtube-websocket/src
COPY --from=yt-build /build/tsconfig.json ./youtube-websocket/tsconfig.json
COPY --from=yt-build /build/package.json ./youtube-websocket/package.json

# Create data directory (will be mounted as volume)
RUN mkdir -p /app/data

# Expose ports: Go backend (1535) + YouTube WS (9905)
EXPOSE 1535 9905

# Start both services
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
