#!/bin/bash
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

set -e

VERSION_FILE=version.txt
BINARY_NAME=thunder
VERSION=$(cat "$VERSION_FILE")
PRODUCT_FOLDER=${BINARY_NAME}-${VERSION}

# Server ports
BACKEND_PORT=8090

# Directories
OUTPUT_DIR=target
BUILD_DIR=$OUTPUT_DIR/.build
BACKEND_BASE_DIR=backend
BACKEND_DIR=$BACKEND_BASE_DIR/cmd/server
REPOSITORY_DIR=$BACKEND_BASE_DIR/cmd/server/repository
REPOSITORY_DB_DIR=$REPOSITORY_DIR/database
SERVER_SCRIPTS_DIR=$BACKEND_BASE_DIR/scripts
SERVER_DB_SCRIPTS_DIR=$BACKEND_BASE_DIR/dbscripts
SECURITY_DIR=repository/resources/security
SAMPLE_BASE_DIR=samples
SAMPLE_OAUTH_APP_DIR=$SAMPLE_BASE_DIR/apps/oauth

GOOS=${2:-darwin}
GOARCH=${3:-arm64}

function clean() {
    echo "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR"
}

function build_backend() {
    echo "Building Go backend..."
    mkdir -p "$BUILD_DIR"

    GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -C "$BACKEND_BASE_DIR" \
    -x -ldflags "-X \"main.version=$VERSION\" \
    -X \"main.buildDate=$$(date -u '+%Y-%m-%d %H:%M:%S UTC')\"" \
    -o "../$BUILD_DIR/$BINARY_NAME" ./cmd/server

    echo "Initializing databases..."
    initialize_databases
}

function initialize_databases() {
    echo "Initializing SQLite databases..."

    mkdir -p "$REPOSITORY_DB_DIR"

    db_files=("thunderdb.db" "runtimedb.db")
    script_paths=("thunderdb/sqlite.sql" "runtimedb/sqlite.sql")

    for ((i = 0; i < ${#db_files[@]}; i++)); do
        db_file="${db_files[$i]}"
        script_rel_path="${script_paths[$i]}"
        db_path="$REPOSITORY_DB_DIR/$db_file"
        script_path="$SERVER_DB_SCRIPTS_DIR/$script_rel_path"

        if [[ -f "$script_path" ]]; then
            if [[ -f "$db_path" ]]; then
                echo " - Removing existing $db_file"
                rm "$db_path"
            fi

            echo " - Creating $db_file using $script_path"
            sqlite3 "$db_path" < "$script_path"
        else
            echo " ! Skipping $db_file: SQL script not found at $script_path"
        fi
    done

    echo "SQLite database initialization complete."
}

function prepare_backend_for_packaging() {
    echo "Copying backend artifacts..."

    cp "$BUILD_DIR/$BINARY_NAME" "$OUTPUT_DIR/$PRODUCT_FOLDER/"
    cp -r "$REPOSITORY_DIR" "$OUTPUT_DIR/$PRODUCT_FOLDER/"
    cp "$VERSION_FILE" "$OUTPUT_DIR/$PRODUCT_FOLDER/"
    cp -r "$SERVER_SCRIPTS_DIR" "$OUTPUT_DIR/$PRODUCT_FOLDER/"
    cp -r "$SERVER_DB_SCRIPTS_DIR" "$OUTPUT_DIR/$PRODUCT_FOLDER/"
    mkdir -p "$OUTPUT_DIR/$PRODUCT_FOLDER/$SECURITY_DIR"

    echo "=== Ensuring server certificates exist in the distribution ==="
    ensure_certificates "$OUTPUT_DIR/$PRODUCT_FOLDER/$SECURITY_DIR"
}

function package() {
    echo "Packaging artifacts..."

    mkdir -p "$OUTPUT_DIR/$PRODUCT_FOLDER"

    prepare_backend_for_packaging

    cp -r "start.sh" "$OUTPUT_DIR/$PRODUCT_FOLDER"

    echo "Creating zip file..."
    (cd "$OUTPUT_DIR" && zip -r "$PRODUCT_FOLDER.zip" "$PRODUCT_FOLDER")
    rm -rf "${OUTPUT_DIR:?}/$PRODUCT_FOLDER" "$BUILD_DIR"
}

function test_integration() {
    echo "Running integration tests..."
    go run -C ./tests/integration ./main.go
}

function ensure_certificates() {
    local cert_dir=$1
    local cert_name_prefix="server"
    local cert_file="$cert_dir/${cert_name_prefix}.cert"
    local key_file="$cert_dir/${cert_name_prefix}.key"

    if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
        mkdir -p "$cert_dir"
        echo "Generating SSL certificates in $cert_dir..."
        OPENSSL_ERR=$(
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$key_file" \
                -out "$cert_file" \
                -subj "/O=WSO2/OU=Thunder/CN=localhost" \
                > /dev/null 2>&1
        )
        if [[ $? -ne 0 ]]; then
            echo "Error generating SSL certificates: $OPENSSL_ERR"
            exit 1
        fi
        echo "Certificates generated successfully in $cert_dir."
    else
        echo "Certificates already exist in $cert_dir."
    fi
}

function run() {
    echo "=== Cleaning build output ==="
    clean

    echo "=== Building backend ==="
    build_backend

    echo "=== Ensuring server certificates exist ==="
    ensure_certificates "$BACKEND_DIR/$SECURITY_DIR"

    echo "=== Ensuring sample app certificates exist ==="
    ensure_certificates "$SAMPLE_OAUTH_APP_DIR"

    # Kill known ports
    function kill_port() {
        local port=$1
        lsof -ti tcp:$port | xargs kill -9 2>/dev/null || true
    }

    kill_port $BACKEND_PORT

    echo "=== Starting backend ==="
    BACKEND_PORT=$BACKEND_PORT go run -C "$BACKEND_DIR" . &
    BACKEND_PID=$!

    echo ""
    echo "⚡ Thunder Backend : https://localhost:$BACKEND_PORT"
    echo "Press Ctrl+C to stop."

    trap 'echo -e "\nStopping servers..."; kill $BACKEND_PID; exit' SIGINT

    wait $BACKEND_PID
}

case "$1" in
    clean)
        clean
        ;;
    build)
        build_backend
        package
        ;;
    test)
        test_integration
        ;;
    run)
        run
        ;;
    *)
        echo "Usage: ./build.sh {clean|build|test|run} [OS] [ARCH]"
        exit 1
        ;;
esac
