# Debian slim instead of Alpine — our crate set (sqlx, jsonwebtoken, argon2,
# rocket_prometheus) pulls native OpenSSL / libpq bindings that don't build
# cleanly against musl. Image is ~80 MB bigger but the build just works.
FROM rust:1-slim-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dpsim-api
# Copy manifest + build.rs first so dependency compilation can be cached.
COPY Cargo.toml Cargo.lock Rocket.toml build.rs ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && cargo build --release \
    && rm -rf src

COPY src/       ./src/
COPY templates/ ./templates/
# Force cargo to rebuild the binary crate (touch to invalidate the stub above).
RUN touch src/main.rs && cargo build --release

# Runtime image — keeps TLS / certs for the sqlx tokio-rustls build.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/dpsim-api/target/release/dpsim-api /usr/bin/dpsim-api
COPY --from=builder /usr/src/dpsim-api/templates/ /usr/bin/templates/
COPY --from=builder /usr/src/dpsim-api/Rocket.toml /usr/bin/Rocket.toml

# Non-root runtime user (docs/43 #10). The API only reads its baked-in
# templates + Rocket.toml and opens :8000 — no filesystem writes needed,
# and uploads are streamed straight to the file-service URL. Running as
# root added zero capability and broadened the blast radius if a future
# dependency ever had an RCE.
RUN useradd --system --shell /usr/sbin/nologin --uid 10001 dpsim
USER dpsim:dpsim

WORKDIR /usr/bin
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=2s --retries=10 \
    CMD wget -q -O- http://localhost:8000/healthz || exit 1
CMD ["/usr/bin/dpsim-api"]
