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

// Package store defines the database queries for user schema management operations.
package store

import "github.com/asgardeo/thunder/internal/system/database/model"

var (
	// QueryGetUserSchemaCount retrieves the total count of user schemas.
	QueryGetUserSchemaCount = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-001",
		PostgresQuery: `
			SELECT COUNT(*) AS total 
			FROM user_schemas`,
		SQLiteQuery: `
			SELECT COUNT(*) AS total 
			FROM user_schemas`,
	}

	// QueryGetUserSchemaList retrieves a paginated list of user schemas.
	QueryGetUserSchemaList = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-002",
		PostgresQuery: `
			SELECT schema_id, name
			FROM user_schemas
			ORDER BY name
			LIMIT $1 OFFSET $2`,
		SQLiteQuery: `
			SELECT schema_id, name
			FROM user_schemas
			ORDER BY name
			LIMIT ? OFFSET ?`,
	}

	// QueryCreateUserSchema creates a new user schema.
	QueryCreateUserSchema = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-003",
		PostgresQuery: `
			INSERT INTO user_schemas (schema_id, name, schema_def)
			VALUES ($1, $2, $3)`,
		SQLiteQuery: `
			INSERT INTO user_schemas (schema_id, name, schema_def)
			VALUES (?, ?, ?)`,
	}

	// QueryGetUserSchemaByID retrieves a user schema by its ID.
	QueryGetUserSchemaByID = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-004",
		PostgresQuery: `
			SELECT schema_id, name, schema_def
			FROM user_schemas
			WHERE schema_id = $1`,
		SQLiteQuery: `
			SELECT schema_id, name, schema_def
			FROM user_schemas
			WHERE schema_id = ?`,
	}

	// QueryGetUserSchemaByName retrieves a user schema by its name.
	QueryGetUserSchemaByName = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-005",
		PostgresQuery: `
			SELECT schema_id, name, schema_def
			FROM user_schemas
			WHERE name = $1`,
		SQLiteQuery: `
			SELECT schema_id, name, schema_def
			FROM user_schemas
			WHERE name = ?`,
	}

	// QueryUpdateUserSchemaByID updates a user schema by its ID.
	QueryUpdateUserSchemaByID = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-006",
		PostgresQuery: `
			UPDATE user_schemas
			SET name = $2, schema_def = $3
			WHERE schema_id = $1`,
		SQLiteQuery: `
			UPDATE user_schemas
			SET name = ?, schema_def = ?
			WHERE schema_id = ?`,
	}

	// QueryDeleteUserSchemaByID deletes a user schema by its ID.
	QueryDeleteUserSchemaByID = model.DBQuery{
		ID: "ASQ-USER_SCHEMA-007",
		PostgresQuery: `
			DELETE FROM user_schemas
			WHERE schema_id = $1`,
		SQLiteQuery: `
			DELETE FROM user_schemas
			WHERE schema_id = ?`,
	}
)
