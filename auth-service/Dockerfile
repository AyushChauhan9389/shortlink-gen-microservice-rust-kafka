# ---- Builder Stage ----

FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y build-essential

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release -p auth-service

# ---- Final Stage ----
FROM debian:bookworm-slim

COPY --from=builder /usr/src/app/target/release/auth-service /usr/local/bin/auth-service

CMD ["auth-service"]