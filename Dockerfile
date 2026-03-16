FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

ENV PORT=9000
ENV REMODEX_PUSH_STATE_FILE=/data/push-state.json

RUN addgroup -S relay && adduser -S relay -G relay
RUN mkdir -p /data && chown -R relay:relay /data

COPY --from=builder /app/target/release/remodex-relay /usr/local/bin/remodex-relay

USER relay

EXPOSE 9000

CMD ["remodex-relay"]
