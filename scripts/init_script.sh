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

# Validate required arguments
if [ "$#" -ne 6 ]; then
  echo "Usage: $0 <db_type> <db_hostname> <db_port> <db_name> <db_username> <db_password>"
  exit 1
fi

DB_TYPE=$1
DB_HOSTNAME=$2
DB_PORT=$3
DB_NAME=$4
DB_USERNAME=$5
DB_PASSWORD=$6

# Execute the database schema script
echo "Initializing the database..."

case "$DB_TYPE" in
  postgres)
    SCHEMA_FILE="./dbscripts/postgresql.sql"
    if [ ! -f "$SCHEMA_FILE" ]; then
      echo "Database schema file not found: $SCHEMA_FILE"
      exit 1
    fi

    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOSTNAME" -p "$DB_PORT" -U "$DB_USERNAME" -d "$DB_NAME" -f "$SCHEMA_FILE"
    ;;
  sqlite)
    SCHEMA_FILE="dbscripts/sqlite.sql"
    if [ ! -f "$SCHEMA_FILE" ]; then
      echo "Database schema file not found: $SCHEMA_FILE"
      exit 1
    fi

    # Ensure the directory for the database file exists
    DB_DIR=$(dirname "$DB_NAME")
    if [ ! -d "$DB_DIR" ]; then
      echo "Database directory not found. Creating directory: $DB_DIR"
      mkdir -p "$DB_DIR"
    fi

    if [ ! -f "$DB_NAME" ]; then
      echo "Database file not found. Creating and initializing the database..."
      sqlite3 "$DB_NAME" < "$SCHEMA_FILE"
    else
      echo "Database file already exists. Skipping initialization."
    fi
    ;;
  *)
    echo "Unsupported database type: $DB_TYPE"
    exit 1
    ;;
esac

if [ $? -eq 0 ]; then
  echo "Database initialization completed successfully."
else
  echo "Database initialization failed."
  exit 1
fi
