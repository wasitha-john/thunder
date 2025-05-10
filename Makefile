# ----------------------------------------------------------------------------
# Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

# Constants
VERSION_FILE=version.txt
VERSION=$(shell cat $(VERSION_FILE))
BINARY_NAME=thunder

# Directories
FRONTEND_DIR=frontend/loginportal
BACKEND_DIR=backend/cmd/server

# Default target
all: prepare clean build test

prepare:
	chmod +x build.sh

clean:
	./build.sh clean

build:
	./build.sh build

test:
	./build.sh test

run:
	./build.sh run

help:
	@echo "Makefile targets:"
	@echo "  all    - Clean, build, and test the project."
	@echo "  clean  - Remove build artifacts."
	@echo "  build  - Build the Go project and frontend, then package."
	@echo "  test   - Run integration tests."
	@echo "  run    - Build and run the application locally."
	@echo "  help   - Show this help message."

.PHONY: all prepare clean build test run help
