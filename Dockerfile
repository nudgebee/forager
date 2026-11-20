# UBI9 go-toolset (Go 1.27.3) satisfies go.mod's 1.26.x floor.
FROM registry.access.redhat.com/ubi9/go-toolset:1.27.3-1795042432 AS build-stage
# Always compile with the base image's Go, never an auto-downloaded toolchain.
ENV GOTOOLCHAIN=local
USER root

WORKDIR /app

# Install Oracle Instant Client (basiclite + SDK) for godror CGO build.
# Uses Oracle's "latest" URL which always points to the current release.
RUN dnf install -y --setopt=install_weak_deps=0 --nodocs libaio unzip && \
    curl -fsSLO https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip && \
    curl -fsSLO https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip && \
    unzip -q instantclient-basiclite-linuxx64.zip -d /opt/oracle && \
    unzip -oq instantclient-sdk-linuxx64.zip -d /opt/oracle && \
    rm -f instantclient-*.zip && \
    OCI_DIR=$(ls -d /opt/oracle/instantclient_* | head -1) && \
    echo "$OCI_DIR" > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig && \
    dnf clean all

COPY go.mod go.sum ./

RUN go mod download

COPY . ./

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

ENV CGO_ENABLED=1
RUN OCI_DIR=$(ls -d /opt/oracle/instantclient_* | head -1) && \
    export LD_LIBRARY_PATH="$OCI_DIR" && \
    VERSION_PKG=nudgebee/forager/pkg/version && \
    go build -tags oracle \
      -ldflags "-s -w -X ${VERSION_PKG}.Version=${VERSION} -X ${VERSION_PKG}.Commit=${COMMIT} -X ${VERSION_PKG}.BuildTime=${BUILD_TIME}" \
      -o /app/nudgebee-forager ./cmd
RUN chmod +x /app/nudgebee-forager


FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1794186349 AS release-stage

ARG VERSION=dev
ARG IMAGE_RELEASE=1
LABEL name="nudgebee-forager" \
      maintainer="nudgebee" \
      vendor="nudgebee" \
      version="${VERSION}" \
      release="${IMAGE_RELEASE}" \
      summary="Nudgebee Forager proxy agent" \
      description="Nudgebee Forager proxy agent: connects to Nudgebee and proxies requests to private databases and services."

# microdnf update patches the pinned base to the latest UBI9 errata.
# OS_PKG_EPOCH: bump (ISO week) to bust the cached package layer when a scan
# flags a stale package.
ARG OS_PKG_EPOCH=2026-W47
RUN echo "os-pkg-epoch: ${OS_PKG_EPOCH}" && \
    microdnf update -y --nodocs --setopt=install_weak_deps=0 && \
    microdnf install -y --nodocs --setopt=install_weak_deps=0 ca-certificates libaio shadow-utils && \
    microdnf clean all && rm -rf /var/cache/dnf /var/cache/yum

WORKDIR /app
COPY --from=build-stage /app/nudgebee-forager /app/nudgebee-forager
COPY --from=build-stage /opt/oracle/instantclient_* /opt/oracle/instantclient/
COPY LICENSE NOTICE /licenses/
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient

RUN groupadd --system --gid 10001 nudgebee && \
    useradd --system --no-create-home --uid 10001 --gid nudgebee nudgebee && \
    mkdir -p /data && chown nudgebee:root /data && chmod g=u /data && \
    microdnf remove -y shadow-utils && microdnf clean all
USER 10001

ENV NB_DATA_DIR=/data

CMD ["./nudgebee-forager"]
