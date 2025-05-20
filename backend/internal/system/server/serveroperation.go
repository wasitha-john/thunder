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

// Package server provides server wide operations and utilities.
package server

import (
	dbprovider "github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// GetAllowedOrigins retrieves the allowed origins from the database.
func GetAllowedOrigins() ([]string, error) {
	logger := log.GetLogger()

	dbClient, err := dbprovider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, err
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Error closing database client", log.Error(closeErr))
		}
	}()

	results, err := dbClient.Query(QueryAllowedOrigins)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, err
	}

	if len(results) == 0 {
		logger.Debug("No allowed origins found")
		return []string{}, nil
	}

	row := results[0]
	allowedOrigins, ok := row["allowed_origins"].(string)
	if !ok {
		logger.Error("Failed to parse allowed_origins as string")
		return nil, err
	}

	return utils.ParseStringArray(allowedOrigins), nil
}
