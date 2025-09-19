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
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
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
	GetDBClient(dbName string) (DBClientInterface, error)
}

// DBProvider is the implementation of DBProviderInterface.
type DBProvider struct {
	identityClient DBClientInterface
	runtimeClient  DBClientInterface
	identityMutex  sync.RWMutex
	runtimeMutex   sync.RWMutex
}

var (
	instance *DBProvider
	once     sync.Once
)

// GetDBProvider returns the instance of DBProvider.
func GetDBProvider() DBProviderInterface {
	once.Do(func() {
		instance = &DBProvider{}
		instance.closeOnInterrupt()
	})
	return instance
}

// closeOnInterrupt sets up signal handling for graceful shutdown
func (d *DBProvider) closeOnInterrupt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logger := log.GetLogger()
		if err := d.close(); err != nil {
			logger.Error("Error closing database connections", log.Error(err))
		} else {
			logger.Debug("Database connections closed successfully")
		}
	}()
}

// GetDBClient returns a database client based on the provided database name.
// Not required to close the returned client manually since it manages its own connection pool.
func (d *DBProvider) GetDBClient(dbName string) (DBClientInterface, error) {
	switch dbName {
	case "identity":
		return d.getIdentityClient()
	case "runtime":
		return d.getRuntimeClient()
	default:
		return nil, fmt.Errorf("unsupported database name: %s", dbName)
	}
}

// getIdentityClient returns the identity client, initializing it if necessary.
func (d *DBProvider) getIdentityClient() (DBClientInterface, error) {
	d.identityMutex.RLock()
	if d.identityClient != nil {
		client := d.identityClient
		d.identityMutex.RUnlock()
		return client, nil
	}
	d.identityMutex.RUnlock()

	d.identityMutex.Lock()
	defer d.identityMutex.Unlock()

	if d.identityClient != nil {
		return d.identityClient, nil
	}

	if err := d.initializeIdentityClient(); err != nil {
		return nil, err
	}

	return d.identityClient, nil
}

// getRuntimeClient returns the runtime client, initializing it if necessary.
func (d *DBProvider) getRuntimeClient() (DBClientInterface, error) {
	d.runtimeMutex.RLock()
	if d.runtimeClient != nil {
		client := d.runtimeClient
		d.runtimeMutex.RUnlock()
		return client, nil
	}
	d.runtimeMutex.RUnlock()

	d.runtimeMutex.Lock()
	defer d.runtimeMutex.Unlock()

	if d.runtimeClient != nil {
		return d.runtimeClient, nil
	}

	if err := d.initializeRuntimeClient(); err != nil {
		return nil, err
	}

	return d.runtimeClient, nil
}

// initializeIdentityClient initializes the identity database client.
func (d *DBProvider) initializeIdentityClient() error {
	config := config.GetThunderRuntime().Config.Database

	identityClient, err := d.createClient(config.Identity, "identity")
	if err != nil {
		d.identityClient = nil
		return fmt.Errorf("failed to initialize identity client: %w", err)
	}

	d.identityClient = identityClient
	return nil
}

// initializeRuntimeClient initializes the runtime database client.
func (d *DBProvider) initializeRuntimeClient() error {
	config := config.GetThunderRuntime().Config.Database

	runtimeClient, err := d.createClient(config.Runtime, "runtime")
	if err != nil {
		d.runtimeClient = nil
		return fmt.Errorf("failed to initialize runtime client: %w", err)
	}

	d.runtimeClient = runtimeClient
	return nil
}

// createClient creates a database client with connection pool configuration from config.
func (d *DBProvider) createClient(dataSource config.DataSource, dbName string) (DBClientInterface, error) {
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

	return NewDBClient(db, dbConfig.driverName), nil
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

// close closes the database connections
func (d *DBProvider) close() error {
	var identityErr, runtimeErr error

	d.identityMutex.Lock()
	if d.identityClient != nil {
		if client, ok := d.identityClient.(*DBClient); ok {
			if err := client.close(); err != nil {
				identityErr = fmt.Errorf("failed to close identity client: %w", err)
			}
		}
		d.identityClient = nil
	}
	d.identityMutex.Unlock()

	d.runtimeMutex.Lock()
	if d.runtimeClient != nil {
		if client, ok := d.runtimeClient.(*DBClient); ok {
			if err := client.close(); err != nil {
				runtimeErr = fmt.Errorf("failed to close runtime client: %w", err)
			}
		}
		d.runtimeClient = nil
	}
	d.runtimeMutex.Unlock()

	return errors.Join(identityErr, runtimeErr)
}
