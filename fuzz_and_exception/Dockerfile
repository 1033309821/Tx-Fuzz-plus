FROM golang:1.23.8-alpine3.20 AS builder

WORKDIR /build
# Copy and download dependencies using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/tx-fuzz.bin ./cmd/fuzz

FROM alpine:latest

COPY --from=builder /build/tx-fuzz.bin /tx-fuzz.bin

ENTRYPOINT ["/tx-fuzz.bin"]
