# WSO2 Thunder ⚡
### The Lighting Fast Identity Management Suite

**Project Thunder** is a modern, identity management service by WSO2. It empowers you to design tailored login, registration, and recovery flows using a flexible identity flow designer.

Thunder secures users, applications, services, and AI agents by managing their identities and offering a complete suite of supporting capabilities.

Designed for extensibility, scalability, and seamless containerized deployment, Thunder integrates naturally with microservices and DevOps environments—serving as the core identity layer for your cloud platform.

---

## 🚀 Features

- ✅ **Standards-Based**
  - OAuth 2/ OpenID Connect (OIDC): Authorization Code, Client Credentials
- 🔗 **Login Options:** Basic Authentication, Login with GitHub
- 🌐 **RESTful APIs:** User Management, Application Management

---

## ⚡ Quickstart

### ✅ Prerequisites

- Node.js 14+

### Step 1: Download the distribution from the latest release

Download `thunder-<version>.zip` from the [latest release](https://github.com/asgardeo/thunder/releases/latest).

### Step 2: Unzip and start the product

```bash
unzip thunder-v0.0.1.zip
cd thunder-v0.0.1/
sh start.sh
```

### Step 3: Tryout the product

#### 1️⃣ Create a User

Create a user in the system to tryout the authentication flows. You can use the following cURL command to create a user with the required attributes.

  ```bash
  curl --location 'https://localhost:8090/users' \
  --header 'Content-Type: application/json' \
  --data-raw '{
      "organizationUnit": "456e8400-e29b-41d4-a716-446655440001",
      "type": "superhuman",
      "attributes": {
          "username": "thor",
          "password": "thor123",
          "email": "thor@thunder.sky",
          "firstName": "Thor",
          "lastName": "Odinson",
          "age": 1534,
          "abilities": [
              "strength",
              "speed",
              "healing"
          ],
          "address": {
              "city": "Asgard",
              "zip": "00100"
          }
      }
  }'
  ```

#### 2️⃣ Try Out Client Credentials Flow

```bash
curl -k -X POST https://localhost:8090/oauth2/token \
  -d 'grant_type=client_credentials' \
  -u 'client123:secret123'
```

#### 2️⃣ Try Out Authorization Code Flow

- Open the following URL in your browser:

  ```bash
  https://localhost:8090/oauth2/authorize?response_type=code&client_id=client123&redirect_uri=https://localhost:3000&scope=openid&state=state_1
  ```

- Enter the credentials of the user you created in the previous step.

- After successful authentication, you will be redirected to the redirect URI with the authorization code and state.

  ```bash

  https://localhost:3000/?code=<code>&state=state_1
  ```

- Copy the authorization code and exchange it for an access token using the following cURL command:

  ```bash
  curl -k -X POST 'https://localhost:8090/oauth2/token' \
  -u 'client123:secret123' \
  -d 'grant_type=authorization_code' \
  -d 'redirect_uri=https://localhost:3000' \
  -d 'code=<code>'
  ```

  - **Client ID:** `client123`
  - **Client Secret:** `secret123`

#### 3️⃣ Try App Native Login

##### 1️⃣ Login with Basic Authentication

- Create an application and configure the basic auth login template for it.
  ```bash
  curl --location 'https://localhost:8090/applications' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{
      "client_id": "client456",
      "client_secret": "***",
      "callback_url": [
          "https://localhost:3000"
      ],
      "auth_flow_graph_id": "auth_flow_config_basic",
      "description": "Sample application for App native login",
      "name": "App Native Login"
  }'
  ```

- Start login flow for the application with the following cURL command:

  ```bash
  curl --location 'https://localhost:8090/flow/execution' \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --data '{
      "applicationId": "<application_id>",
  }
  '
  ```

  You'll receive a response similar to the following:

  ```json
  {
      "flowId": "db93a19e-c23f-4cfc-a45f-0e0bc157f6d5",
      "flowStatus": "PROMPT_ONLY",
      "type": "VIEW",
      "inputs": [
          {
              "name": "username",
              "type": "string",
              "required": true
          },
          {
              "name": "password",
              "type": "string",
              "required": true
          }
      ]
  }
  ```

- Make the second cURL request to complete the login flow. Make sure to replace `<flow_id>` with the `flowId` received in the previous response.

  ```bash
  curl --location 'https://localhost:8090/flow/execution' \
  --header 'Content-Type: application/json' \
  --data '{
      "flowId": "<flow_id>",
      "inputs": {
          "username": "thor",
          "password": "thor123"
      }
  }
  '
  ```

- If the login is successful, you will receive a response with the auth assertion.

##### 2️⃣ Login with GitHub

- Create an OAuth application in your Github account following the instructions given in the [Github documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).
  - Configure home page and callback URLs as per your application.
  - Copy the **Client ID** and **Client Secret**.

- Update the system created github IDP by invoking the IDP management API with the following cURL command. Make sure to replace `<client_id>`, `<client_secret>`, and `<app_callback_url>` with the values you copied from your GitHub OAuth application.

  ```bash
  curl --location --request PUT 'https://localhost:8090/identity-providers/550e8400-e29b-41d4-a716-446655440001' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Github",
      "description": "Login with Github",
      "client_id": "<client_id>",
      "client_secret": "<client_secret>",
      "redirect_uri": "<app_callback_url>",
      "scopes": [
          "user:email",
          "read:user"
      ]
  }'
  ```

- Create an application and configure the GitHub login template for it.

  ```bash
  curl --location 'https://localhost:8090/applications' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{
      "client_id": "client456",
      "client_secret": "***",
      "callback_url": [
          "https://localhost:3000"
      ],
      "auth_flow_graph_id": "auth_flow_config_github",
      "description": "Sample application for App native login",
      "name": "App Native Login"
  }'
  ```

- Start login flow for the application with the following cURL command:

  ```bash
  curl --location 'https://localhost:8090/flow/execution' \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --data '{
      "applicationId": "<application_id>",
  }
  '
  ```

  You'll receive a response similar to the following:

  ```json
  {
      "flowId": "80d57e64-8082-4096-bb0e-22b2187f8265",
      "flowStatus": "INCOMPLETE",
      "type": "REDIRECTION",
      "inputs": [
          {
              "name": "code",
              "type": "string",
              "required": true
          }
      ],
      "additionalInfo": {
          "redirect_url": "<github_auth_redirect_url>"
      }
  }
  ```

- Open the `redirect_url` in your browser. You will be redirected to the GitHub login page. Enter your GitHub credentials and authorize the application.
- After successful authentication, you will be redirected to the redirect URI with the authorization code and state.

  ```bash
  https://localhost:3000/?code=<code>&state=80d57e64-8082-4096-bb0e-22b2187f8265
  ```

- Copy the authorization code and make the second cURL request to complete the login flow. Make sure to replace `<flow_id>` with the `flowId` received in the previous response.

  ```bash
  curl --location 'https://localhost:8090/flow/execution' \
  --header 'Content-Type: application/json' \
  --data '{
      "flowId": "<flow_id>",
      "inputs": {
          "code": "<code>"
      }
  }
  '
  ```

- If the login is successful, you will receive a response with the auth assertion.

## ⚡ Build the Product from Source

### ✅ Prerequisites

- Go 1.23+
- Node.js 14+

---

- Build the product with tests using the following command:

```bash
make all
```

- Start the product using the following command:

```bash
make run
```
---

## 🔑 Try Out the Sample App

- Create a file `.env` in the path `samples/apps/oauth/` and add below values.

  ```
  VITE_REACT_APP_SERVER_FLOW_ENDPOINT=https://localhost:8090/flow
  VITE_REACT_APPLICATIONS_ENDPOINT=https://localhost:8090/applications
  VITE_REACT_APP_BASIC_AUTH_APP_ID=550e8400-e29b-41d4-a716-446655440000
  VITE_REACT_APP_REDIRECT_BASED_LOGIN=false
  ```

- Run the sample app using the following commands:

  ```bash
  cd samples/apps/oauth && npm i && npm start
  ```
  
- Open your browser and navigate to `https://localhost:3000` to see the sample app in action.

---

## 🗄️ Running with PostgreSQL Database

### 🔧 Step 1: Start PostgreSQL

- Create a Docker container for PostgreSQL with `thunderdb` database.

  ```bash
  docker run -d -p 5432:5432 --name postgres \
    -e POSTGRES_USER=asgthunder \
    -e POSTGRES_PASSWORD=asgthunder \
    -e POSTGRES_DB=thunderdb \
    postgres
  ```

- Create the `runtimedb` in the same PostgreSQL container.

  ```bash
  docker exec -it postgres psql -U asgthunder -d thunderdb -c "CREATE DATABASE runtimedb;"
  ```

### 🗂 Step 2: Initialize the Database

- Populate the `thunderdb` database with the required tables and data.

  ```bash
  docker exec -i postgres psql -U asgthunder -d thunderdb < backend/dbscripts/thunderdb/postgress.sql
  ```

- Populate the `runtimedb` database with the required tables and data.

  ```bash
  docker exec -i postgres psql -U asgthunder -d thunderdb < backend/dbscripts/runtimedb/postgress.sql
  ```

### 🛠 Step 3: Configure Thunder to Use PostgreSQL

1. Open the `backend/cmd/server/repository/conf/deployment.yaml` file.
2. Update the `database` section to point to the PostgreSQL database:
```yaml
database:
  identity:
    type: "postgres"
    hostname: "localhost"
    port: 5432
    name: "thunderdb"
    username: "asgthunder"
    password: "asgthunder"
    sslmode: "disable"
  runtime:
    type: "postgres"
    hostname: "localhost"
    port: 5432
    name: "runtimedb"
    username: "asgthunder"
    password: "asgthunder"
    sslmode: "disable"
```

### ▶️ Step 4: Run the Product

   ```bash
   make run
   ```

The product will now use the PostgreSQL database for its operations.

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.

---------------------------------------------------------------------------
(c) Copyright 2025 WSO2 LLC.
