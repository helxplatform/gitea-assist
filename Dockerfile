# Use the official Golang image to build the binary
FROM golang:1.20 AS build
ENV CGO_ENABLED 0
ARG BINARY_NAME
# Set the working directory
WORKDIR /app

# Copy the Go source files, Makefile, etc.
COPY . .

# Install make
RUN apt-get update && apt-get install -y make

# Use the Makefile to build the Go application
RUN make build

# Using a multi-stage build
FROM alpine:3.18
ARG BINARY_NAME

# Ensure we have a valid user and group
RUN addgroup -g 1000 -S assistant && \
  adduser -u 1000 -G assistant -S assistant

COPY --from=build --chown=assistant:assistant "/app/{$BINARY_NAME}" /app/
# Expose port 8080
EXPOSE 8080

WORKDIR /app

# Run the compiled binary
CMD ["./assistant"]
