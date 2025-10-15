# GitHub Copilot Custom Instructions

## Project Overview

This repository is a lightweight user and identity management product written in Go. The primary focus is to provide authentication and authorization capabilities for applications and also to allow managing users, roles, and permissions. The server allows three different approaches to authenticate users: by using standard protocols such as OAuth2, OIDC, by defining a flexible orchestration flow, or by using individual authentication mechanisms such as password, passwordless, and social login.

The project is structured as a monorepo to manage the backend, frontend, and sample applications in a single repository. The backend code is located in the `/backend` directory. There is an optional Next.js frontend in `/frontend` and a sample React Vite app in `/samples/apps`.

## Tech Stack

### Backend

- Go (Golang) latest stable version is used.
- Recommended database is PostgreSQL. SQLite is by default packaged for testing and local development purposes.

### Frontend

- Next.js with TypeScript is used for the frontend.
- React with Vite and TypeScript is used for the sample app.

### Testing

- `stretchr/testify` is used to write unit tests.
- `mockery` is used to generate mocks for unit tests.
- `DATA-DOG/go-sqlmock` is used to mock database operations in unit tests.

## Project Structure

- backend/: Server backend implementation.
  - cmd/server/: Main server application.
    - repository/: Configurations and other resource files.
  - dbscripts/: Database scripts.
  - internal/: Internal packages for various functionalities.
    - authn/: Individual authentication-related code.
    - oauth/: OAuth related codes such as OAuth, OAuth2, AuthZ, OIDC, etc.
    - flow/: Flow orchestration engine and related code.
    - executor/: Individual flow executor implementations.
    - system/: Common utilities, services, and configurations.
  - scripts/: Utility scripts such as init scripts.
  - tests/: Common unit tests related files.
    - mocks/: Generated mocks for unit tests.
    - resources/: Test resource files.
  - .mockery.yml: Mockery configurations related to mock generation.
- frontend/: Individual frontend application code.
  - apps/gate/: Gate app implementation which serves UIs for login, registration and recovery. 
  - packages/: Common frontend packages such as UI components, services, and contexts.
- install/helm/: Helm charts for deployment.
- samples/apps/: Sample applications demonstrating the usage of the product.
  - oauth/: Sample React Vite app implementing authentication with OAuth2 and flow execution APIs.
- tests/integration/: Integration tests for the backend.
- docs/: Documentation related files.
  - apis/: Swagger definitions for APIs.
  - content/: Other documentation files.

## General Guidelines

- Follow general coding best practices, design patterns, and security recommendations.
- Ensure all identity-related code aligns with relevant RFC specifications.
- Follow https://wso2.com/whitepapers/wso2-rest-apis-design-guidelines/ for RESTful API design.
- Follow https://security.docs.wso2.com/en/latest/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/ for secure coding practices.
- Promote code reusability and define constants where applicable.
- Ensure proper error handling and logging.
- Write unit tests to achieve at least 80% coverage and integration tests where applicable.
- Refer project README for other general instructions such as build the product, run the server, run tests, etc.

## Backend Specific Guidelines

### General
- Reuse common utilities from the `internal/system` packages.
- Define interfaces for services where applicable to allow dependency injection.

### Logging
- Use the `log` package in `internal/system` for logging.
- Add minimal info logs and ensure server errors are logged for debugging.
- Avoid logging PII. Use `MaskString` from `internal/system/log` to mask sensitive information.
- Add debug logs where necessary, but avoid excessive logging.
- Use `IsDebugEnabled` from `internal/system/log` if excessive handling is done for debugging log construction.

### Database
- Use `DBClient` in `internal/system/database` for database operations.
- Use `DBQuery` in `internal/system/database` to define queries with a unique ID. This allows for DB-specific queries where needed.

### HTTP
- Use `HTTPClient` in `internal/system/http` for sending external requests.

### Cache
- Extend `BaseCache` in `internal/system/cache` for caching requirements.

### Config
- Use `ThunderRuntime` in `internal/system/config` to read system configs.

### Server Constants
- Use constants defined in `internal/system/constants` for reusable global values.

### Error Handling
- Use `ServiceError` from `internal/system/error/serviceerror` to return errors from service layer.
- Use `ErrorResponse` from `internal/system/error/apierror` to define and return API layer errors.
- Avoid logging the same error twice. Return a Go error or `ServiceError` from internal components and log at the service layer.
- Avoid returning unnecessary details from the API layer for server-side errors. Log and return a generic message like "Internal server error" or "Something went wrong" where applicable.

### Defining APIs
- Return JSON responses from APIs where applicable.
- Return JSON errors as per the server `ErrorResponse` definition. For 500 internal server errors, a generic message may be returned.
- Define each API service in a new file in `internal/system/services`, extending `ServiceInterface`. Define CORS policies where applicable.
- Register the API service in `internal/system/managers/servicemanager.go`.

### Service Provider
- Use a provider to return service objects/structs for other services. Define the provider when creating a new instance for other services and use that provider variable to obtain the service instance.
- This allows injecting services during unit tests. Keep provider logic minimal, as it won't be tested.

### Testing

#### Unit Tests
- Ensure unit tests are written to achieve at least 80% coverage.
- Use `stretchr/testify` for tests and follow the test suite pattern.
- `mockery` is used to generate mocks; configurations are in `/backend/.mockery.yml`.
- Place generated mocks in the `/backend/tests/mocks/` directory.
- Unit tests can be run using `make test_unit` command from the project root directory. Alternatively `go test` command can also be used from the `/backend` directory with applicable flags.

#### Integration Tests
- Write integration tests in the `/tests/integration/` directory where applicable.
- Add unit and integrations tests for each new feature or bug fix to achieve a combined coverage of at least 80%.
- Integration tests can be run using `make all` command from the project root directory. This will build the project, package into a zip, unzip in a temp directory, and run the integration tests. So it will take some time to complete. Integration tests can be run on an already built product by executing the `make test_integration` command from the project root directory.

### Documentation
- Ensure applicable changes are documented in the `README` file or `/docs/content/` directory.
- Ensure each new feature or API is documented.
- Add Swagger definitions for the APIs to `/docs/apis/`.
