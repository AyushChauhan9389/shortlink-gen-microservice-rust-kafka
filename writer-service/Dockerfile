# ---- Builder Stage ----
FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y build-essential

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release -p writer-service

# ---- Final Stage ----
FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/target/release/writer-service /usr/local/bin/writer-service
CMD ["writer-service"]
