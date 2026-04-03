FROM golang:1.25-bookworm AS build-stage

WORKDIR /app

# Install Oracle Instant Client (basiclite + SDK) for godror CGO build
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 unzip wget && \
    wget -q https://download.oracle.com/otn_software/linux/instantclient/2340000/instantclient-basiclite-linux.x64-23.4.0.24.05dbru.zip && \
    wget -q https://download.oracle.com/otn_software/linux/instantclient/2340000/instantclient-sdk-linux.x64-23.4.0.24.05dbru.zip && \
    unzip -q instantclient-basiclite-linux.x64-*.zip -d /opt/oracle && \
    unzip -q instantclient-sdk-linux.x64-*.zip -d /opt/oracle && \
    rm -f instantclient-*.zip && \
    echo /opt/oracle/instantclient_23_4 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./

RUN go mod download

COPY . ./
ENV CGO_ENABLED=1
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_23_4
RUN go build -tags oracle -o /app/nudgebee-forager ./cmd
RUN chmod +x /app/nudgebee-forager


FROM debian:bookworm-slim AS release-stage

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libaio1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build-stage /app/nudgebee-forager /app/nudgebee-forager
COPY --from=build-stage /opt/oracle/instantclient_23_4 /opt/oracle/instantclient_23_4
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_23_4

RUN groupadd --system nudgebee && useradd --system --no-create-home --gid nudgebee nudgebee
RUN mkdir -p /data && chown nudgebee:nudgebee /data
USER nudgebee

ENV NB_DATA_DIR=/data

CMD ["./nudgebee-forager"]
