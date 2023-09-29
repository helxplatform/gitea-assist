# Use the official Golang image to build the binary
FROM golang:1.20 AS build
ENV CGO_ENABLED 0
ARG BINARY_NAME
# Set the working directory
WORKDIR /app

# Copy the Go source files, Makefile, etc.
COPY . .

# Build the Go application passing BINARY_NAME from Makefile (local development)
# or Github Action Build-Arg. 
RUN go build -o ${BINARY_NAME}

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
