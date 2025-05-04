# Variables
BINARY_NAME=thunder
OUTPUT_DIR=target
ZIP_FILE=product-is-thunder.zip
REPOSITORY_DIR=cmd/server/repository
VERSION_FILE=version.txt

# Default target
all: clean build package

# Build the Go project
build:
	go build -o $(OUTPUT_DIR)/$(BINARY_NAME) ./cmd/server

# Package the binary and repository directory into a zip file
package: build
	VERSION=$(shell cat $(VERSION_FILE)) && \
	mkdir -p $(OUTPUT_DIR)/thunder-$$VERSION && \
	cp $(OUTPUT_DIR)/$(BINARY_NAME) $(OUTPUT_DIR)/thunder-$$VERSION/ && \
	cp -r $(REPOSITORY_DIR) $(OUTPUT_DIR)/thunder-$$VERSION/ && \
	cp $(VERSION_FILE) $(OUTPUT_DIR)/thunder-$$VERSION/ && \
	cp -r scripts $(OUTPUT_DIR)/thunder-$$VERSION/ && \
	cp -r dbscripts $(OUTPUT_DIR)/thunder-$$VERSION/ && \
	cd $(OUTPUT_DIR) && zip -r thunder-$$VERSION.zip thunder-$$VERSION && \
	rm -rf thunder-$$VERSION && \
	rm $(BINARY_NAME)

# Clean up build artifacts
clean:
	rm -rf $(OUTPUT_DIR)

.PHONY: all build package clean
