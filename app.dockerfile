FROM golang:1.24.3-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o auth-service ./cmd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .

EXPOSE 8080

CMD ["./auth-service"]