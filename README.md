# ⚡ Asgardeo Thunder — Cloud-Native Identity Management

**Asgardeo Thunder** is a modern, cloud-native identity management service. It empowers you to design tailored login, registration, and recovery flows using a flexible identity flow designer.

Thunder secures users, applications, services, and AI agents by managing their identities and offering a complete suite of supporting capabilities.

Designed for extensibility, scalability, and seamless containerized deployment, Thunder integrates naturally with microservices and DevOps environments—serving as the core identity layer for your cloud platform.

---

## 🚀 Features

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
- Docker
- cURL
- Node.js 14+
- React 19+

---

### 🔧 Step 1: Start PostgreSQL

```bash
docker run -d -p 5432:5432 --name postgres \
  -e POSTGRES_USER=asgthunder \
  -e POSTGRES_PASSWORD=asgthunder \
  -e POSTGRES_DB=thunderdb \
  postgres
```

### 🗂 Step 2: Initialize the Database

```bash
docker exec -i postgres psql -U asgthunder -d thunderdb < dbscripts/postgress.sql
```

---

### 🛠 Step 3: Build the Product

```bash
make all
```

---

### ▶️ Step 4: Run the Product

```bash
cd target
unzip thunder-1.0.0-m1-SNAPSHOT.zip
cd thunder-1.0.0-m1-SNAPSHOT
./thunder
```

---

### 🔑 Step 5: Try Out Client Credentials Flow

```bash
curl -k -X POST https://localhost:8090/oauth2/token \
  -H 'Authorization: Basic Y2xpZW50MTIzOnNlY3JldDEyMw==' \
  -d 'grant_type=client_credentials'
```

- **Client ID:** `client123`
- **Client Secret:** `secret123`

---

## 🧪 Running Integration Tests

Building the product with `make all` will run the integration tests by default. However if you want to run the tests manually, follow the steps below.

### 1️⃣ Build the Project

```bash
make clean build
```

### 2️⃣ Run the Tests

```bash
make test
```

## Running Development Environment

### 🔧 Step 1: Start PostgreSQL

```bash
docker run -d -p 5432:5432 --name postgres \
  -e POSTGRES_USER=asgthunder \
  -e POSTGRES_PASSWORD=asgthunder \
  -e POSTGRES_DB=thunderdb \
  postgres
```

### 🗂 Step 2: Initialize the Database

```bash
docker exec -i postgres psql -U asgthunder -d thunderdb < dbscripts/postgress.sql
```

### 🛠 Step 3: Run the Product

```bash
make run
```
