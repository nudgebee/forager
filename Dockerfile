FROM golang:1.25-alpine AS build-stage

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/nudgebee-forager ./cmd
RUN chmod +x /app/nudgebee-forager


FROM alpine:3.19 AS release-stage

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=build-stage /app/nudgebee-forager /app/nudgebee-forager

RUN addgroup -S nudgebee && adduser -S nudgebee -G nudgebee
RUN mkdir -p /data && chown nudgebee:nudgebee /data
USER nudgebee

ENV NB_DATA_DIR=/data

CMD ["./nudgebee-forager"]
