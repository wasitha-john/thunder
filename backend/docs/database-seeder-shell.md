# Database Data Seeding with Shell Scripts

This document describes the shell script-based approach for seeding initial data into Thunder databases.

## Overview

The data seeding functionality has been implemented using shell scripts that follow the same pattern as the existing database schema initialization. This approach provides consistency with the current build workflow and separation of concerns between schema definition and data population.

## Components

### 1. SQL Data Files

**Location**: `backend/dbscripts/thunderdb/`

- `seed_data_sqlite.sql` - SQLite-specific data seeding statements
- `seed_data_postgres.sql` - PostgreSQL-specific data seeding statements

These files contain `INSERT` statements with appropriate conflict resolution:
- SQLite: `INSERT OR IGNORE`
- PostgreSQL: `INSERT ... ON CONFLICT ... DO NOTHING`

### 2. Data Seeding Script

**Location**: `backend/scripts/seed_data.sh`

A shell script that handles data seeding for both SQLite and PostgreSQL databases.

#### Features:
- **Database agnostic**: Supports both SQLite and PostgreSQL
- **Idempotent**: Checks for existing data and skips seeding unless forced
- **Error handling**: Proper validation and error reporting
- **Force option**: Allows re-seeding when needed

#### Usage:

```bash
# SQLite seeding
./backend/scripts/seed_data.sh -type sqlite -seed path/to/seed_data_sqlite.sql -path path/to/database.db

# PostgreSQL seeding
./backend/scripts/seed_data.sh -type postgres -seed path/to/seed_data_postgres.sql \
  -host localhost -port 5432 -name thunder -username user -password pass

# Force re-seeding
./backend/scripts/seed_data.sh -type sqlite -seed path/to/seed_data_sqlite.sql -path path/to/database.db -force
```

### 3. Build Integration

The data seeding is integrated into the `build.sh` script and runs automatically after database schema initialization.

**Modified functions in `build.sh`:**
- `seed_databases()` - New function that handles seeding for all databases
- Updated build process to call seeding after schema initialization

## Data Seeded

The following initial data is seeded into the database:

1. **Applications (SP_APP)**
   - Test SPA application with OAuth configuration

2. **OAuth Consumer Apps (IDN_OAUTH_CONSUMER_APPS)**
   - Client credentials and configuration for test application

3. **Inbound Authentication (SP_INBOUND_AUTH)**
   - OAuth2 authentication configuration

4. **Allowed Origins (IDN_OAUTH_ALLOWED_ORIGINS)**
   - CORS origins for development

5. **Organization Units (ORGANIZATION_UNIT)**
   - Hierarchical organization structure (root, engineering, sales, frontend)

6. **Users (USER)**
   - Sample user with attributes

7. **Identity Providers (IDP)**
   - Local, GitHub, and Google identity providers with properties

## Advantages of Shell Script Approach

1. **Consistency**: Follows the same pattern as existing database initialization
2. **Independence**: Can be run separately from application startup
3. **Build Integration**: Seamlessly integrates with existing build workflows
4. **Simplicity**: Easy to understand and maintain
5. **Database Agnostic**: Handles both SQLite and PostgreSQL with appropriate syntax
6. **Idempotency**: Safe to run multiple times without duplicating data

## Integration with Build Process

The seeding is automatically triggered during:
1. `./build.sh build` - Full build process
2. `./build.sh run` - Development run process

The seeding happens after schema initialization but before application startup, ensuring the database is fully prepared.

## Testing

The implementation includes:
- Idempotency testing (multiple runs don't create duplicates)
- Error handling validation
- Database-specific syntax verification
- Integration with existing build workflows

## Migration from Go-based Seeder

This shell script approach replaces the previous Go-based seeder implementation while maintaining the same functionality and improving consistency with the project's database initialization patterns.