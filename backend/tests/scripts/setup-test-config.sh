#!/bin/bash

DB_TYPE=${DB_TYPE:-sqlite}

cat > backend/tests/resources/deployment.yaml <<EOF
server:
  hostname: localhost
  port: 8080

gate_client:
  hostname: localhost
  port: 9090
  scheme: https
  login_path: /login
  error_path: /error

security:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem

database:
EOF

if [ "$DB_TYPE" = "postgres" ]; then
  cat >> backend/tests/resources/deployment.yaml <<EOF
  identity:
    type: postgres
    hostname: localhost
    port: 5432
    name: identity_db
    username: postgres
    password: postgres
    sslmode: disable
    path: ""
    options: ""

  runtime:
    type: postgres
    hostname: localhost
    port: 5432
    name: runtime_db
    username: postgres
    password: postgres
    sslmode: disable
    path: ""
    options: ""
EOF
else
  cat >> backend/tests/resources/deployment.yaml <<EOF
  identity:
    type: sqlite
    hostname: ""
    port: 0
    name: ""
    username: ""
    password: ""
    sslmode: ""
    path: ":memory:"
    options: "cache=shared"

  runtime:
    type: sqlite
    hostname: ""
    port: 0
    name: ""
    username: ""
    password: ""
    sslmode: ""
    path: "/data/runtime.db"
    options: "cache=shared"
EOF
fi

cat >> backend/tests/resources/deployment.yaml <<EOF

oauth:
  jwt:
    issuer: thunder
    validity_period: 3600

flow:
  graph_directory: "repository/resources/graphs/"
  authn:
    default_flow: "auth_flow_config_basic"
EOF
