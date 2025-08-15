#!/bin/bash
# ----------------------------------------------------------------------------
# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

# Data seeder script for Thunder database
# This script seeds initial data into the database after schema initialization

# Script common variables.
TYPE=""
SEED_FILE_PATH=""
FORCE_SEED="false"

# Database connection details.
HOST=""
PORT=""
NAME=""
DB_PATH=""
USERNAME=""
PASSWORD=""

print_help() {
  echo ""
  echo "Usage:"
  echo "  $0 [OPTIONS]"
  echo ""
  echo "Options:"
  printf "  %-12s %s\n" "-type" "Type of the database (e.g., postgres, sqlite) [required]"
  printf "  %-12s %s\n" "-seed" "Path to the database seed data file [required]"
  printf "  %-12s %s\n" "-force" "Flag to force seeding (re-run even if already seeded)"
  printf "  %-12s %s\n" "-host" "Database host (required for postgres)"
  printf "  %-12s %s\n" "-port" "Database port (required for postgres)"
  printf "  %-12s %s\n" "-name" "Database name [required]"
  printf "  %-12s %s\n" "-path" "Path to the SQLite database file (required for sqlite)"
  printf "  %-12s %s\n" "-username" "Database username (required for postgres)"
  printf "  %-12s %s\n" "-password" "Database password (required for postgres)"
  printf "  %-12s %s\n" "-h, --help" "Show this help message and exit"
  echo ""
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -type) TYPE="$2"; shift 2;;
      -seed) SEED_FILE_PATH="$2"; shift 2;;
      -force) FORCE_SEED="true"; shift;;
      -host) HOST="$2"; shift 2;;
      -port) PORT="$2"; shift 2;;
      -name) NAME="$2"; shift 2;;
      -path) DB_PATH="$2"; shift 2;;
      -username) USERNAME="$2"; shift 2;;
      -password) PASSWORD="$2"; shift 2;;
      -h|--help) print_help; exit 0;;
      *) echo "Unknown parameter passed: $1"; exit 1;;
    esac
  done
}

validate_inputs() {
  if [ -z "$SEED_FILE_PATH" ]; then
    echo "Seed file path is required. Please provide it using -seed."
    echo "Use -h or --help for usage information."
    exit 1
  fi

  if [ ! -f "$SEED_FILE_PATH" ]; then
    echo "Seed file not found: $SEED_FILE_PATH"
    exit 1
  fi

  if [ -z "$TYPE" ]; then
    echo "Database type is required. Please provide it using -type."
    echo "Use -h or --help for usage information."
    exit 1
  fi

  if [ "$TYPE" = "postgres" ]; then
    if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$NAME" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
      echo "PostgreSQL connection details are required. Please provide -host, -port, -name, -username, and -password."
      echo "Use -h or --help for usage information."
      exit 1
    fi
  elif [ "$TYPE" = "sqlite" ]; then
    if [ -z "$DB_PATH" ]; then
      echo "SQLite database path is required. Please provide it using -path."
      echo "Use -h or --help for usage information."
      exit 1
    fi
    
    if [ ! -f "$DB_PATH" ]; then
      echo "SQLite database file not found: $DB_PATH"
      echo "Please ensure the database schema is initialized first."
      exit 1
    fi
  else
    echo "Unsupported database type: $TYPE"
    exit 1
  fi
}

check_seeding_status() {
  local already_seeded=false
  
  if [ "$TYPE" = "postgres" ]; then
    # Check if data already exists by looking for the test app
    local count=$(PGPASSWORD="$PASSWORD" psql -h "$HOST" -p "$PORT" -U "$USERNAME" -d "$NAME" -Atc "SELECT COUNT(*) FROM SP_APP WHERE APP_ID = '550e8400-e29b-41d4-a716-446655440000';" 2>/dev/null)
    if [ "$count" -gt 0 ]; then
      already_seeded=true
    fi
  elif [ "$TYPE" = "sqlite" ]; then
    # Check if data already exists by looking for the test app
    local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM SP_APP WHERE APP_ID = '550e8400-e29b-41d4-a716-446655440000';" 2>/dev/null)
    if [ "$count" -gt 0 ]; then
      already_seeded=true
    fi
  fi
  
  if [ "$already_seeded" = true ]; then
    if [ "$FORCE_SEED" = "true" ]; then
      echo "Data already exists but force seeding is enabled. Proceeding..."
      return 0
    else
      echo "Database appears to already have seed data. Use -force to re-seed."
      echo "Seeding skipped."
      exit 0
    fi
  fi
}

seed_postgres() {
  echo "Seeding data into PostgreSQL database..."
  PGPASSWORD="$PASSWORD" psql -h "$HOST" -p "$PORT" -U "$USERNAME" -d "$NAME" -f "$SEED_FILE_PATH"
  if [ $? -ne 0 ]; then
    echo "Failed to seed data into PostgreSQL database."
    exit 1
  fi
}

seed_sqlite() {
  echo "Seeding data into SQLite database..."
  sqlite3 "$DB_PATH" < "$SEED_FILE_PATH"
  if [ $? -ne 0 ]; then
    echo "Failed to seed data into SQLite database."
    exit 1
  fi
}

seed_database() {
  echo "Seeding the database with initial data..."
  case "$TYPE" in
    postgres) seed_postgres;;
    sqlite) seed_sqlite;;
    *) echo "Unsupported database type: $TYPE"; exit 1;;
  esac
  echo "Database seeding completed successfully."
}

main() {
  echo "Running database data seeder script..."
  echo ""
  parse_args "$@"
  validate_inputs
  check_seeding_status
  seed_database
  echo ""
  echo "Database seeding script completed."
}

main "$@"
