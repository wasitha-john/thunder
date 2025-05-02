/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// DBClientInterface defines the interface for database operations.
type DBClientInterface interface {
	ExecuteQuery(query string, args ...interface{}) ([]map[string]interface{}, error)
	Close() error
}

// DBClient is the implementation of DBClientInterface.
type DBClient struct {
	db *sql.DB
}

// GetDriver creates a new DBClient instance for the given database type and configuration.
func GetDriver(dbType string, cfg *config.Config) (DBClientInterface, error) {

	var dsn string
	var driverName string

	switch dbType {
	case "identity":
		dbConfig := cfg.Database.Identity
		switch dbConfig.Type {
		case "postgres":
			driverName = "postgres"
			dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
				dbConfig.Hostname, dbConfig.Port, dbConfig.Username, dbConfig.Password, dbConfig.Name, dbConfig.SSLMode)
		default:
			return nil, fmt.Errorf("unsupported database type: %s", dbConfig.Type)
		}
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Test the database connection.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return &DBClient{db: db}, nil
}

// ExecuteQuery executes a SELECT query and returns the result as a slice of maps.
func (client *DBClient) ExecuteQuery(query string, args ...interface{}) ([]map[string]interface{}, error) {

	logger := log.GetLogger()
	logger.Info("Executing query", zap.String("query", query), zap.Any("args", args))

	rows, err := client.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	results := []map[string]interface{}{}
	for rows.Next() {
		row := make([]interface{}, len(columns))
		rowPointers := make([]interface{}, len(columns))
		for i := range row {
			rowPointers[i] = &row[i]
		}

		if err := rows.Scan(rowPointers...); err != nil {
			return nil, err
		}

		result := map[string]interface{}{}
		for i, col := range columns {
			result[col] = row[i]
		}
		results = append(results, result)
	}

	return results, nil
}

// Close closes the database connection.
func (client *DBClient) Close() error {

	return client.db.Close()
}

// ParseStringArray parses a comma-separated string into a slice of strings.
func ParseStringArray(value interface{}) []string {

	if value == nil {
		return []string{}
	}
	return strings.Split(value.(string), ",")
}
