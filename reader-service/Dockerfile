# ---- Builder Stage ----
FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y build-essential

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release -p reader-service

# ---- Final Stage ----
FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/target/release/reader-service /usr/local/bin/reader-service
CMD ["reader-service"]
