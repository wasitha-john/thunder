/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package provider provides functionality for managing database connections and clients.
package provider

import (
	"database/sql"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/database/client"
)

const (
	dataSourceTypePostgres = "postgres"
	dataSourceTypeSQLite   = "sqlite"
)

// dbConfig represents the local database configuration.
type dbConfig struct {
	dsn        string
	driverName string
}

// DBProviderInterface defines the interface for getting database clients.
type DBProviderInterface interface {
	GetDBClient(dbName string) (client.DBClientInterface, error)
	Close() error
}

// DBProvider is the implementation of DBProviderInterface.
type DBProvider struct {
	identityClient client.DBClientInterface
	runtimeClient  client.DBClientInterface
}

var (
	instance *DBProvider
	once     sync.Once
)

// GetDBProvider returns the instance of DBProvider.
func GetDBProvider() DBProviderInterface {
	once.Do(func() {
		instance = &DBProvider{}
		instance.initializeClients()
	})
	return instance
}

// GetDBClient returns a database client based on the provided database name.
// Do not close the returned client manually since it manages its own connection pool.
func (d *DBProvider) GetDBClient(dbName string) (client.DBClientInterface, error) {
	switch dbName {
	case "identity":
		if d.identityClient == nil {
			return nil, fmt.Errorf("identity client not initialized - check database configuration")
		}
		return d.identityClient, nil
	case "runtime":
		if d.runtimeClient == nil {
			return nil, fmt.Errorf("runtime client not initialized - check database configuration")
		}
		return d.runtimeClient, nil
	default:
		return nil, fmt.Errorf("unsupported database name: %s", dbName)
	}
}

// initializeClients initializes the database clients.
func (d *DBProvider) initializeClients() {
	config := config.GetThunderRuntime().Config.Database

	identityClient, err := d.createClient(config.Identity, "identity")
	if err != nil {
		d.identityClient = nil
	} else {
		d.identityClient = identityClient
	}

	runtimeClient, err := d.createClient(config.Runtime, "runtime")
	if err != nil {
		d.runtimeClient = nil
	} else {
		d.runtimeClient = runtimeClient
	}
}

// createClient creates a database client with connection pool configuration from config.
func (d *DBProvider) createClient(dataSource config.DataSource, dbName string) (client.DBClientInterface, error) {
	dbConfig := d.getDBConfig(dataSource)

	db, err := sql.Open(dbConfig.driverName, dbConfig.dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database %s: %w", dbName, err)
	}

	// Configure connection pool using values from configuration
	db.SetMaxOpenConns(dataSource.MaxOpenConns)
	db.SetMaxIdleConns(dataSource.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(dataSource.ConnMaxLifetime) * time.Second)

	// Test the database connection.
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to ping database %s: %w (close error: %w)", dbName, err, closeErr)
		}
		return nil, fmt.Errorf("failed to ping database %s: %w", dbName, err)
	}

	// Enable foreign key constraints for SQLite databases
	if dbConfig.driverName == dataSourceTypeSQLite {
		_, err := db.Exec("PRAGMA foreign_keys = ON;")
		if err != nil {
			if closeErr := db.Close(); closeErr != nil {
				return nil, fmt.Errorf("failed to enable foreign key constraints for %s: %w (close error: %w)",
					dbName, err, closeErr)
			}
			return nil, fmt.Errorf("failed to enable foreign key constraints for %s: %w", dbName, err)
		}
	}

	return client.NewDBClient(db, dbConfig.driverName), nil
}

// getDBConfig returns the database configuration based on the provided data source.
func (d *DBProvider) getDBConfig(dataSource config.DataSource) dbConfig {
	var dbConfig dbConfig

	switch dataSource.Type {
	case dataSourceTypePostgres:
		dbConfig.driverName = dataSourceTypePostgres
		dbConfig.dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			dataSource.Hostname, dataSource.Port, dataSource.Username, dataSource.Password,
			dataSource.Name, dataSource.SSLMode)
	case dataSourceTypeSQLite:
		dbConfig.driverName = dataSourceTypeSQLite
		options := dataSource.Options
		if options != "" && options[0] != '?' {
			options = "?" + options
		}
		dbConfig.dsn = fmt.Sprintf("%s%s", path.Join(config.GetThunderRuntime().ThunderHome, dataSource.Path), options)
	}

	return dbConfig
}

// Close gracefully closes all database connections.
func (d *DBProvider) Close() error {
	var errs []error

	if d.identityClient != nil {
		if err := d.identityClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close identity client: %w", err))
		}
		d.identityClient = nil
	}

	if d.runtimeClient != nil {
		if err := d.runtimeClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close runtime client: %w", err))
		}
		d.runtimeClient = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing database clients: %v", errs)
	}

	return nil
}
