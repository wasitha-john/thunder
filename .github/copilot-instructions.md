# GitHub Copilot Custom Instructions

## Project Overview
This repository is a lightweight user and identity management product written in Go. The backend code is located in the `/backend` directory. There is an optional Next.js frontend in `/frontend` and a sample React Vite app in `/samples/apps`.

## General Guidelines
- Follow general coding best practices, design patterns, and security recommendations.
- Ensure all identity-related code aligns with relevant RFC specifications.
- Promote code reusability and define constants where applicable.

## Backend Project Guidelines

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
- Ensure unit tests are written to achieve at least 80% coverage.
- Write integration tests in the `/tests/integration/` directory where applicable.
- Use `stretchr/testify` for tests and follow the test suite pattern.
- `mockery` is used to generate mocks; configurations are in `/backend/.mockery.yml`.

### Documentation
- Add or update documentation in the `README` file or `/docs/content/` for new features or API changes.
- Add Swagger definitions for each new API to `/docs/apis/`.
