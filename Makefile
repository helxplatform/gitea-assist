# Makefile

# Variable for the binary name
BINARY_NAME=assistant
# Variable for the container name
REGISTRY_NAME=containers.renci.org/helxplatform
CONTAINER_NAME=gitea-assist:latest

# Build the Go application
build:
	@echo "Building Go application..."
	go build -o $(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Build the Docker container
docker-build: build
	@echo "Building Docker container..."
	docker build -t $(CONTAINER_NAME) .

# Push the Docker container
docker-push: docker-build
	@echo "Pushing Docker container..."
	docker tag $(CONTAINER_NAME) $(REGISTRY_NAME)/$(CONTAINER_NAME)
	docker push $(REGISTRY_NAME)/$(CONTAINER_NAME)

# Clean up
clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)

.PHONY: build test docker-build clean
