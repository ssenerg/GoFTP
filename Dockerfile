# Go cross-compiles: images for other platforms (--platform) build without
# emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/goftp . && \
    mkdir /out/data && mkdir -p /out/dirs && mkdir -m 1777 /out/dirs/cache

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/goftp /usr/local/bin/goftp
# Uploads need /data to be writable by the nonroot user; new volumes copy
# this ownership. Thumbnails go in /cache, whichever user goftp runs as
# (copied with its parent, which keeps its mode).
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/dirs/ /
ENV GOFTP_DIR=/data GOFTP_CACHE_DIR=/cache
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["goftp"]
CMD ["serve"]
