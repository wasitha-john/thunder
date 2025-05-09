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

# Initialize variables
DB=""
TYPE=""
HOST=""
PORT=""
NAME=""
USERNAME=""
PASSWORD=""
RECREATE="false"

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -db) DB="$2"; shift 2;;
    -type) TYPE="$2"; shift 2;;
    -host) HOST="$2"; shift 2;;
    -port) PORT="$2"; shift 2;;
    -name) NAME="$2"; shift 2;;
    -username) USERNAME="$2"; shift 2;;
    -password) PASSWORD="$2"; shift 2;;
    -recreate) RECREATE="true"; shift;;
    *) echo "Unknown parameter passed: $1"; exit 1;;
  esac
done

# Validate required arguments
if [ -z "$DB" ] || [ -z "$TYPE" ] || [ -z "$NAME" ]; then
  echo "Usage: $0 -db <db> -type <type> -name <name> [-host <host> -port <port> -username <username> -password <password> (required for postgres)]"
  exit 1
fi

if [ "$TYPE" = "postgres" ]; then
  if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "For postgres, -host, -port, -username, and -password are required."
    exit 1
  fi
fi

# Check if the type is provided
if [ -z "$DB" ]; then
  echo "DB is not provided. Please provide a valid db type."
  exit 1
fi

# Check if the type is valid
if [ "$DB" != "thunderdb" ] && [ "$DB" != "runtimedb" ]; then
  echo "Invalid DB type provided. Please provide either 'thunderdb' or 'runtimedb'."
  exit 1
fi

echo "Initializing the database..."

case "$TYPE" in
  postgres)
    SCHEMA_FILE="../../backend/dbscripts/$DB/postgresql.sql"
    if [ ! -f "$SCHEMA_FILE" ]; then
      echo "Database schema file not found: $SCHEMA_FILE"
      exit 1
    fi

    if [ "$RECREATE" = "true" ]; then
      echo "Dropping existing database..."
      PGPASSWORD="$PASSWORD" psql -h "$HOST" -p "$PORT" -U "$USERNAME" -c "DROP DATABASE IF EXISTS $NAME;"
      if [ $? -ne 0 ]; then
        echo "Failed to drop existing database."
        exit 1
      fi
      echo "Creating new database..."
      PGPASSWORD="$PASSWORD" psql -h "$HOST" -p "$PORT" -U "$USERNAME" -c "CREATE DATABASE $NAME;"
      if [ $? -ne 0 ]; then
        echo "Failed to create new database."
        exit 1
      fi
    fi

    PGPASSWORD="$PASSWORD" psql -h "$HOST" -p "$PORT" -U "$USERNAME" -d "$NAME" -f "$SCHEMA_FILE"
    ;;
  sqlite)
    SCHEMA_FILE="../../backend/dbscripts/$DB/sqlite.sql"
    if [ ! -f "$SCHEMA_FILE" ]; then
      echo "Database schema file not found: $SCHEMA_FILE"
      exit 1
    fi

    # Ensure the directory for the database file exists
    DB_DIR=$(dirname "$NAME")
    if [ ! -d "$DB_DIR" ]; then
      echo "Database directory not found. Creating directory: $DB_DIR"
      mkdir -p "$DB_DIR"
    fi

    if [ "$RECREATE" = "true" ] && [ -f "$NAME" ]; then
      echo "Removing existing SQLite database file..."
      rm -f "$NAME"
    fi

    if [ ! -f "$NAME" ]; then
      echo "Creating and initializing the database..."
      sqlite3 "$NAME" < "$SCHEMA_FILE"
    else
      echo "Database file already exists. Skipping initialization."
    fi
    ;;
  *)
    echo "Unsupported database type: $TYPE"
    exit 1
    ;;
esac

if [ $? -eq 0 ]; then
  echo "Database initialization completed successfully."
else
  echo "Database initialization failed."
  exit 1
fi
