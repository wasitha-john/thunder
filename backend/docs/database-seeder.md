# Database Data Seeder

The Thunder application includes a database data seeder that populates initial sample data during server startup. This seeder maintains separation of concerns by keeping database schema definitions separate from initial data seeding.

## Architecture

### Components

- **Schema Files** (`dbscripts/thunderdb/`): Contain only CREATE TABLE statements and database schema definitions
- **Data Seeder** (`internal/system/database/seeder/`): Go-based data seeding implementation

### Key Features

- **Database Agnostic**: Supports both SQLite and PostgreSQL with database-specific queries
- **Idempotent**: Can be run multiple times safely without duplicating data
- **Type Safe**: Data is defined in Go structs with proper typing
- **Integrated**: Runs automatically during server startup
- **Testable**: Includes comprehensive unit and integration tests

## Sample Data

The seeder populates the following initial data:

- **Organization Units**: Root organization with engineering, sales, and frontend teams
- **Applications**: Test SPA application with OAuth configuration
- **Identity Providers**: Local, GitHub, and Google IDPs with properties
- **Users**: Sample user with admin and user roles
- **OAuth Configuration**: Consumer apps, inbound auth, and allowed origins

## Implementation Details

### Seeder Interface

```go
type SeederInterface interface {
    SeedInitialData() error
}
```

### Usage

The seeder is automatically initialized and executed during server startup in `main.go`:

```go
func initDatabaseSeeding(logger *log.Logger) {
    dbProvider := provider.NewDBProvider()
    seederProvider := seeder.NewSeederProvider(dbProvider)
    
    identitySeeder, err := seederProvider.GetSeeder("identity")
    if err != nil {
        logger.Fatal("Failed to get identity database seeder", log.Error(err))
    }
    
    if err := identitySeeder.SeedInitialData(); err != nil {
        logger.Fatal("Failed to seed initial data", log.Error(err))
    }
}
```

### Database Queries

The seeder uses database-specific queries to handle differences between SQLite and PostgreSQL:

```go
query := model.DBQuery{
    ID:            "SEED_INSERT_ORGANIZATION_UNIT",
    SQLiteQuery:   "INSERT OR IGNORE INTO ORGANIZATION_UNIT (...) VALUES (...)",
    PostgresQuery: "INSERT INTO ORGANIZATION_UNIT (...) VALUES (...) ON CONFLICT (OU_ID) DO NOTHING",
}
```

## Testing

The seeder includes comprehensive tests:

- **Unit Tests**: Mock-based testing of seeder functionality
- **Integration Tests**: End-to-end testing with in-memory SQLite database
- **Idempotency Tests**: Verify no duplicate data is created on multiple runs

Run tests with:
```bash
go test ./internal/system/database/seeder/... -v
```

## Configuration

The seeder runs automatically during server startup. No additional configuration is required. If you need to disable seeding or customize the data, you can modify the `getSeedData()` function in `seeddata.go`.