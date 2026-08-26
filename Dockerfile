# ---- build ----
# The frontend (incl. Vue) is vendored as static files and embedded via
# go:embed, so there is no Node/npm build step — only the Go toolchain.
FROM golang:1.22 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/certtracker ./cmd/server

# ---- runtime ----
# distroless/static ships CA certificates (for HTTPS to Teams) and nothing else.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/certtracker /certtracker

EXPOSE 18090
USER nonroot:nonroot
ENTRYPOINT ["/certtracker"]
