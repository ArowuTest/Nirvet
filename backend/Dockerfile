# Nirvet backend — multi-stage, static, distroless non-root image.
# One image ships api + worker + migrate; each deploy target picks the command.
# Portable identically to Render, Cloud Run, GKE, or a sovereign VM (ADR-0005).

FROM golang:1.25.12-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binaries (CGO off) so they run in a distroless/static base.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/api /out/worker /out/migrate /app/
# Non-root by default (distroless nonroot user). No shell, minimal attack surface.
EXPOSE 8080
# Default runs the API; override for the worker (["/app/worker"]) or migrate.
ENTRYPOINT ["/app/api"]
