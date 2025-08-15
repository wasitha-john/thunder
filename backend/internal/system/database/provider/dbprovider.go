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
}

// DBProvider is the implementation of DBProviderInterface.
type DBProvider struct{}

// NewDBProvider creates a new instance of DBProvider.
func NewDBProvider() DBProviderInterface {
	return &DBProvider{}
}

// GetDBClient returns a database client based on the provided database name.
func (d *DBProvider) GetDBClient(dbName string) (client.DBClientInterface, error) {
	// Create the database connection string based on the configured database type.
	config := config.GetThunderRuntime().Config.Database
	var dbConfig dbConfig
	switch dbName {
	case "identity":
		dbConfig = getDBConfig(config.Identity)
	case "runtime":
		dbConfig = getDBConfig(config.Runtime)
	default:
		return nil, fmt.Errorf("unsupported database name: %s", dbName)
	}

	db, err := sql.Open(dbConfig.driverName, dbConfig.dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the database connection.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable foreign key constraints for SQLite databases
	if dbConfig.driverName == dataSourceTypeSQLite {
		_, err := db.Exec("PRAGMA foreign_keys = ON;")
		if err != nil {
			return nil, fmt.Errorf("failed to enable foreign key constraints: %w", err)
		}
	}

	return client.NewDBClient(db, dbConfig.driverName), nil
}

// getDBConfig returns the database configuration based on the provided data source.
func getDBConfig(dataSource config.DataSource) dbConfig {
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
