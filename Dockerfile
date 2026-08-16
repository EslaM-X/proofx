# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>

# proofx in a container. The image bundles the CLI so proofs can be created
# and verified without installing Go.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proofx ./cmd/proofx

FROM alpine:3.20
RUN apk add --no-cache git ca-certificates
COPY --from=build /out/proofx /usr/local/bin/proofx
ENTRYPOINT ["proofx"]
CMD ["help"]
