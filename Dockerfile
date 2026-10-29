# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /out/cas-api . \
    && mkdir -p /out/data

FROM busybox:1.37.0-musl AS healthcheck

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.description="Minimal hardened NetGoat CAS API runtime" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
WORKDIR /app
COPY --from=healthcheck /bin/busybox /busybox
COPY --from=build --chown=nonroot:nonroot /out/cas-api /app/cas-api
COPY --from=build --chown=nonroot:nonroot /out/data /app/data
USER nonroot:nonroot
EXPOSE 8088
ENV CAS_ADDR=:8088 \
    CAS_STATE_FILE=/app/data/cas.json \
    CAS_PUBLIC_URL=http://localhost:8088 \
    GOMEMLIMIT=128MiB
HEALTHCHECK --interval=10s --timeout=3s --retries=8 --start-period=5s CMD ["/busybox", "wget", "-qO-", "http://127.0.0.1:8088/health"]
ENTRYPOINT ["/app/cas-api"]
