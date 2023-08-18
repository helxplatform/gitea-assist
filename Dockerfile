# Use the official Golang image to build the binary
FROM golang:1.20 AS build

# Set the working directory
WORKDIR /app

# Copy the Go source files, Makefile, etc.
COPY . .

# Install make
RUN apt-get update && apt-get install -y make

# Use the Makefile to build the Go application
RUN make build

# Expose port 8080
EXPOSE 8080

# Run the compiled binary
CMD ["/app/assistant"]