FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy source code
COPY src/ ./src/
COPY CMakeLists.txt ./
COPY config/ ./config/

# Build the application
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# Create directories
RUN mkdir -p /app/logs /app/config/zones /app/config/keys

# Create non-root user
RUN useradd -r -s /bin/false rslvd && \
    chown -R rslvd:rslvd /app

# Expose ports
EXPOSE 53/udp 53/tcp 8080/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD dig @localhost -p 53 health.check A || exit 1

USER rslvd

CMD ["./build/rslvd", "-c", "config/rslvd.conf"]
