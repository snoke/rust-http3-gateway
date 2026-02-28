FROM rust:1.88-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/gateway /app/gateway
EXPOSE 8080
EXPOSE 4433
EXPOSE 4433/udp
CMD ["/app/gateway"]
