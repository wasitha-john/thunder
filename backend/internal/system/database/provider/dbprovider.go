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
	identityMutex  sync.RWMutex
	runtimeClient  DBClientInterface
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
		instance.initializeAllClients()
		instance.closeOnInterrupt()
	})
	return instance
}

// GetDBClient returns a database client based on the provided database name.
// Not required to close the returned client manually since it manages its own connection pool.
func (d *DBProvider) GetDBClient(dbName string) (DBClientInterface, error) {
	switch dbName {
	case "identity":
		identityDBConfig := config.GetThunderRuntime().Config.Database.Identity
		return d.getOrInitClient(&d.identityClient, &d.identityMutex, identityDBConfig)
	case "runtime":
		runtimeDBConfig := config.GetThunderRuntime().Config.Database.Runtime
		return d.getOrInitClient(&d.runtimeClient, &d.runtimeMutex, runtimeDBConfig)
	default:
		return nil, fmt.Errorf("unsupported database name: %s", dbName)
	}
}

// initializeAllClients initializes both identity and runtime clients at startup.
func (d *DBProvider) initializeAllClients() {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DBProvider"))

	identityDBConfig := config.GetThunderRuntime().Config.Database.Identity
	err := d.initializeClient(&d.identityClient, identityDBConfig)
	if err != nil {
		logger.Error("Failed to initialize identity database client", log.Error(err))
	}

	runtimeDBConfig := config.GetThunderRuntime().Config.Database.Runtime
	err = d.initializeClient(&d.runtimeClient, runtimeDBConfig)
	if err != nil {
		logger.Error("Failed to initialize runtime database client", log.Error(err))
	}
}

// getOrInitClient gets or initializes a DB client with locking.
func (d *DBProvider) getOrInitClient(
	clientPtr *DBClientInterface,
	mutex *sync.RWMutex,
	dataSource config.DataSource,
) (DBClientInterface, error) {
	mutex.RLock()
	if *clientPtr != nil {
		client := *clientPtr
		mutex.RUnlock()
		return client, nil
	}
	mutex.RUnlock()

	mutex.Lock()
	defer mutex.Unlock()

	if *clientPtr != nil {
		return *clientPtr, nil
	}

	if err := d.initializeClient(clientPtr, dataSource); err != nil {
		return nil, err
	}

	return *clientPtr, nil
}

// initializeClient initializes a database client and assigns it to the provided pointer.
func (d *DBProvider) initializeClient(clientPtr *DBClientInterface, dataSource config.DataSource) error {
	dbConfig := d.getDBConfig(dataSource)
	dbName := dataSource.Name

	db, err := sql.Open(dbConfig.driverName, dbConfig.dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database %s: %w", dbName, err)
	}

	// Configure connection pool using values from configuration
	db.SetMaxOpenConns(dataSource.MaxOpenConns)
	db.SetMaxIdleConns(dataSource.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(dataSource.ConnMaxLifetime) * time.Second)

	// Test the database connection.
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return fmt.Errorf("failed to ping database %s: %w (close error: %w)", dbName, err, closeErr)
		}
		return fmt.Errorf("failed to ping database %s: %w", dbName, err)
	}

	// Enable foreign key constraints for SQLite databases
	if dbConfig.driverName == dataSourceTypeSQLite {
		_, err := db.Exec("PRAGMA foreign_keys = ON;")
		if err != nil {
			if closeErr := db.Close(); closeErr != nil {
				return fmt.Errorf("failed to enable foreign key constraints for %s: %w (close error: %w)",
					dbName, err, closeErr)
			}
			return fmt.Errorf("failed to enable foreign key constraints for %s: %w", dbName, err)
		}
	}

	*clientPtr = NewDBClient(db, dbConfig.driverName)
	return nil
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

// close closes the database connections
func (d *DBProvider) close() error {
	identityErr := d.closeClient(&d.identityClient, &d.identityMutex, "identity")
	runtimeErr := d.closeClient(&d.runtimeClient, &d.runtimeMutex, "runtime")
	return errors.Join(identityErr, runtimeErr)
}

// closeClient is a helper to close a DB client with locking.
func (d *DBProvider) closeClient(clientPtr *DBClientInterface, mutex *sync.RWMutex, clientName string) error {
	mutex.Lock()
	defer mutex.Unlock()
	if *clientPtr != nil {
		if client, ok := (*clientPtr).(*DBClient); ok {
			if err := client.close(); err != nil {
				return fmt.Errorf("failed to close %s client: %w", clientName, err)
			}
		}
		*clientPtr = nil
	}
	return nil
}
