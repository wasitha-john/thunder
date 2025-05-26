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

#### 1️⃣ Try Out Client Credentials Flow

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

- Enter the following credentials:

  - **Username:** `thor`
  - **Password:** `thor123`

    **Note:** The credentials can be configured in the `repository/conf/deployment.yaml` file under the `user_store` section.

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

#### 3️⃣ Configure Login with GitHub

- Create an OAuth application in your Github account following the instructions given in the [Github documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).
  - Configure the urls as follows:
    - **Homepage URL:** `https://localhost:8090`
    - **Authorization callback URL:** `https://localhost:8090/flow/authn`
  - Copy the **Client ID** and **Client Secret**.

- Open the deployment.yaml file in the `backend/cmd/server/repository/conf` directory and add the following configurations:

  ```yaml
  authenticator:
    default: "GithubAuthenticator"
    authenticators:
      - name: "GithubAuthenticator"
        type: "federated"
        display_name: "Github"
        description: "Login with Github"
        client_id: "<client_id>"
        client_secret: "<client_secret>"
        redirect_uri: "https://localhost:8090/flow/authn"
        scopes:
          - "user:email"
          - "read:user"
        additional_params:  # Optional parameters.
          prompt: "select_account"
  ```

- Restart the server.

## ⚡ Build the Product from Source

### ✅ Prerequisites

- Go 1.23+
- Node.js 14+
- PNPM 10+

---

- Build the product with tests using the following command:

```bash
pnpm all
```

- Start the product using the following command:

```bash
pnpm start
```
---

## 🔑 Try Out the Sample App

- Create a file `.env` in the path `samples/apps/oauth/` and add below values

  ```
  VITE_REACT_APP_SERVER_AUTHENTICATION_ENDPOINT=https://localhost:8090/oauth2/authorize
  VITE_REACT_APP_SERVER_TOKEN_ENDPOINT=https://localhost:8090/oauth2/token
  VITE_REACT_APP_CLIENT_ID=client123
  VITE_REACT_APP_CLIENT_SECRET=secret123
  VITE_REACT_APP_REDIRECT_URI=https://localhost:3000
  VITE_REACT_APP_SCOPE=openid
  ```

- And run this command

  ```bash
  pnpm sample:dev
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
   pnpm start
   ```

The product will now use the PostgreSQL database for its operations.

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.

---------------------------------------------------------------------------
(c) Copyright 2025 WSO2 LLC.
