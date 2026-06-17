FROM golang:1.26-bookworm@sha256:5d2b868674b57c9e48cdd39e891acce4196b6926ca6d11e9c270a8f85106203d AS build-stage

WORKDIR /app

# Install Oracle Instant Client (basiclite + SDK) for godror CGO build.
# Uses Oracle's "latest" URL which always points to the current release.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 unzip wget && \
    wget -q https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip && \
    wget -q https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip && \
    unzip -q instantclient-basiclite-linuxx64.zip -d /opt/oracle && \
    unzip -oq instantclient-sdk-linuxx64.zip -d /opt/oracle && \
    rm -f instantclient-*.zip && \
    OCI_DIR=$(ls -d /opt/oracle/instantclient_* | head -1) && \
    echo "$OCI_DIR" > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig && \
    rm -rf /var/lib/apt/lists/*

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


FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS release-stage

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libaio1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build-stage /app/nudgebee-forager /app/nudgebee-forager
COPY --from=build-stage /opt/oracle/instantclient_* /opt/oracle/instantclient/
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient

RUN groupadd --system nudgebee && useradd --system --no-create-home --gid nudgebee nudgebee
RUN mkdir -p /data && chown nudgebee:nudgebee /data
USER nudgebee

ENV NB_DATA_DIR=/data

CMD ["./nudgebee-forager"]
