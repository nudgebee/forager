# The Go toolchain comes from the official image: Red Hat's go-toolset has no 1.27.4 yet,
# and 1.27.4 carries security fixes in cgo and net/http. The build itself runs on UBI 9,
# so the cgo binary links against the same glibc as the runtime image.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS go-dist

FROM registry.access.redhat.com/ubi9/go-toolset:1.27.3-1795042432@sha256:51eef2836e5223c41577757c30544fbfb3f0710f3436b70b82d2195e35fcb743 AS build-stage
COPY --from=go-dist /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH
# Always compile with the copied Go, never an auto-downloaded toolchain.
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


FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1794186349@sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db AS release-stage

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
    microdnf install -y --nodocs --setopt=install_weak_deps=0 ca-certificates libaio && \
    microdnf clean all && rm -rf /var/cache/dnf /var/cache/yum

WORKDIR /app
COPY --from=build-stage /app/nudgebee-forager /app/nudgebee-forager
COPY --from=build-stage /opt/oracle/instantclient_* /opt/oracle/instantclient/
COPY LICENSE NOTICE /licenses/
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient

# Keep uid/gid 999, what earlier images ran as: existing /data volumes hold an enc_key
# readable only by its owner. /data is also group 0 writable for OpenShift's assigned uid.
RUN echo "nudgebee:x:999:999::/app:/sbin/nologin" >> /etc/passwd && \
    echo "nudgebee:x:999:" >> /etc/group && \
    mkdir -p /data && chown 999:0 /data && chmod g=u /data
USER 999

ENV NB_DATA_DIR=/data

CMD ["./nudgebee-forager"]
