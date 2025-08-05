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

package seeder

import (
	"database/sql"
	"testing"

	"github.com/asgardeo/thunder/internal/system/database/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	_ "modernc.org/sqlite"
)

// IntegrationTestSuite is the integration test suite for the seeder package.
type IntegrationTestSuite struct {
	suite.Suite
	db       *sql.DB
	dbClient client.DBClientInterface
	seeder   SeederInterface
}

// SetupSuite sets up the integration test suite.
func (suite *IntegrationTestSuite) SetupSuite() {
	// Create an in-memory SQLite database for testing
	db, err := sql.Open("sqlite", ":memory:")
	assert.NoError(suite.T(), err)
	
	suite.db = db
	suite.dbClient = client.NewDBClient(db, "sqlite")
	suite.seeder = NewDBSeeder(suite.dbClient)
	
	// Create the schema first
	suite.createSchema()
}

// TearDownSuite cleans up after the integration test suite.
func (suite *IntegrationTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// createSchema creates the necessary database schema for testing.
func (suite *IntegrationTestSuite) createSchema() {
	// Create all necessary tables for testing
	tables := []string{
		`CREATE TABLE ORGANIZATION_UNIT (
			OU_ID VARCHAR(36) PRIMARY KEY,
			PARENT_ID VARCHAR(36),
			HANDLE VARCHAR(255) UNIQUE NOT NULL,
			NAME VARCHAR(255) NOT NULL,
			DESCRIPTION TEXT,
			CREATED_AT TEXT DEFAULT (datetime('now')),
			UPDATED_AT TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE SP_APP (
			APP_ID VARCHAR(36) PRIMARY KEY,
			APP_NAME VARCHAR(255) NOT NULL,
			DESCRIPTION TEXT,
			AUTH_FLOW_GRAPH_ID VARCHAR(255),
			REGISTRATION_FLOW_GRAPH_ID VARCHAR(255)
		)`,
		`CREATE TABLE IDN_OAUTH_CONSUMER_APPS (
			CONSUMER_KEY VARCHAR(255) PRIMARY KEY,
			CONSUMER_SECRET VARCHAR(255) NOT NULL,
			APP_ID VARCHAR(36),
			CALLBACK_URIS TEXT,
			GRANT_TYPES TEXT,
			RESPONSE_TYPES TEXT,
			TOKEN_ENDPOINT_AUTH_METHODS TEXT
		)`,
		`CREATE TABLE SP_INBOUND_AUTH (
			INBOUND_AUTH_KEY VARCHAR(255),
			INBOUND_AUTH_TYPE VARCHAR(50),
			APP_ID VARCHAR(36),
			PRIMARY KEY (INBOUND_AUTH_KEY, INBOUND_AUTH_TYPE)
		)`,
		`CREATE TABLE IDN_OAUTH_ALLOWED_ORIGINS (
			ALLOWED_ORIGINS TEXT PRIMARY KEY
		)`,
		`CREATE TABLE USER (
			USER_ID VARCHAR(36) PRIMARY KEY,
			OU_ID VARCHAR(36),
			TYPE VARCHAR(50),
			ATTRIBUTES TEXT,
			CREATED_AT TEXT DEFAULT (datetime('now')),
			UPDATED_AT TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IDP (
			IDP_ID VARCHAR(36) PRIMARY KEY,
			NAME VARCHAR(255) NOT NULL,
			DESCRIPTION TEXT,
			CREATED_AT TEXT DEFAULT (datetime('now')),
			UPDATED_AT TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IDP_PROPERTY (
			IDP_ID VARCHAR(36),
			PROPERTY_NAME VARCHAR(255),
			PROPERTY_VALUE TEXT,
			IS_SECRET VARCHAR(1),
			PRIMARY KEY (IDP_ID, PROPERTY_NAME)
		)`,
	}
	
	for _, table := range tables {
		_, err := suite.db.Exec(table)
		assert.NoError(suite.T(), err, "Failed to create table")
	}
}

// TestSeedInitialData_Integration tests the complete seeding process.
func (suite *IntegrationTestSuite) TestSeedInitialData_Integration() {
	// Seed the data
	err := suite.seeder.SeedInitialData()
	assert.NoError(suite.T(), err)
	
	// Verify that data was seeded correctly
	
	// Check organization units
	rows, err := suite.db.Query("SELECT COUNT(*) FROM ORGANIZATION_UNIT")
	assert.NoError(suite.T(), err)
	
	var count int
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 4, count, "Expected 4 organization units")
	
	// Check applications
	rows, err = suite.db.Query("SELECT COUNT(*) FROM SP_APP")
	assert.NoError(suite.T(), err)
	
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 1, count, "Expected 1 application")
	
	// Check OAuth consumer apps
	rows, err = suite.db.Query("SELECT COUNT(*) FROM IDN_OAUTH_CONSUMER_APPS")
	assert.NoError(suite.T(), err)
	
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 1, count, "Expected 1 OAuth consumer app")
	
	// Check IDPs
	rows, err = suite.db.Query("SELECT COUNT(*) FROM IDP")
	assert.NoError(suite.T(), err)
	
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 3, count, "Expected 3 IDPs")
	
	// Check IDP properties
	rows, err = suite.db.Query("SELECT COUNT(*) FROM IDP_PROPERTY")
	assert.NoError(suite.T(), err)
	
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 8, count, "Expected 8 IDP properties")
	
	// Verify specific data integrity
	rows, err = suite.db.Query("SELECT APP_NAME FROM SP_APP WHERE APP_ID = ?", "550e8400-e29b-41d4-a716-446655440000")
	assert.NoError(suite.T(), err)
	
	var appName string
	if rows.Next() {
		rows.Scan(&appName)
	}
	rows.Close()
	assert.Equal(suite.T(), "Test SPA", appName, "Expected correct app name")
}

// TestSeedInitialData_Idempotent tests that seeding is idempotent.
func (suite *IntegrationTestSuite) TestSeedInitialData_Idempotent() {
	// Seed the data twice
	err := suite.seeder.SeedInitialData()
	assert.NoError(suite.T(), err)
	
	err = suite.seeder.SeedInitialData()
	assert.NoError(suite.T(), err)
	
	// Verify that data count is still the same (no duplicates)
	rows, err := suite.db.Query("SELECT COUNT(*) FROM ORGANIZATION_UNIT")
	assert.NoError(suite.T(), err)
	
	var count int
	if rows.Next() {
		rows.Scan(&count)
	}
	rows.Close()
	assert.Equal(suite.T(), 4, count, "Expected 4 organization units after double seeding")
}

// TestIntegrationTestSuite runs the integration test suite.
func TestIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}