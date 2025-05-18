# ⚡ WSO2 Thunder — Identity Management

**Thunder** is a modern, identity management service by WSO2. It empowers you to design tailored login, registration, and recovery flows using a flexible identity flow designer.

Thunder secures users, applications, services, and AI agents by managing their identities and offering a complete suite of supporting capabilities.

Designed for extensibility, scalability, and seamless containerized deployment, Thunder integrates naturally with microservices and DevOps environments—serving as the core identity layer for your cloud platform.

---

## 🚀 Features (WIP)

- ✅ **Standards-Based**
  - OAuth 2.1, OpenID Connect (OIDC)
  - SCIM 2.0
- 🛠️ **Visual Identity Flow Designer**
- 👤 **User & Identity Management**
- 🔗 **Social Login**
- 🔐 **Multi-Factor Authentication (MFA)**
- 🌐 **RESTful APIs**

---

## ⚡ Quickstart

### ✅ Prerequisites

- Go 1.23+
- cURL
- Node.js 14+
- React 19+

---

### 🛠 Step 1: Build and Run the Product

```bash
make run
```

---

### 🔑 Step 2: Try Out the Product

#### 1️⃣ Try Out Client Credentials Flow

```bash
curl -k -X POST https://localhost:8090/oauth2/token \
  -H 'Authorization: Basic Y2xpZW50MTIzOnNlY3JldDEyMw==' \
  -d 'grant_type=client_credentials'
```

- **Client ID:** `client123`
- **Client Secret:** `secret123`

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
  curl -k --location 'https://localhost:8090/oauth2/token' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --header 'Authorization: Basic Y2xpZW50MTIzOnNlY3JldDEyMw==' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'redirect_uri=https://localhost:3000' \
  --data-urlencode 'code=<code>'
  ```

  - **Client ID:** `client123`
  - **Client Secret:** `secret123`

#### 3️⃣ Configure Login with Github

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
        id: "147b3c7e-0a2f-4d8b-9c5f-a03800000002"
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

---

## 🧪 Running Integration Tests

Building the product with `make all` will run the integration tests by default. However if you want to run the tests manually, follow the steps below.

### 1️⃣ Build the Product

```bash
make clean build
```

### 2️⃣ Run the Tests

```bash
make test
```

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
