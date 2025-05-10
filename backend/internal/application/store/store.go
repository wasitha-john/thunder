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

package store

import (
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/system/database/client"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

func CreateApplication(app model.Application) error {

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer dbClient.Close()

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(QueryCreateApplication.Query, app.Id, app.Name, app.Description)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create SP application: %w", err)
	}

	_, err = tx.Exec(QueryCreateOAuthApplication.Query, app.Id, app.ClientId, app.ClientSecret,
		strings.Join(app.CallbackURLs, ","), strings.Join(app.SupportedGrantTypes, ","))
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create OAuth application: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func GetApplicationList() ([]model.Application, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func(dbc client.DBClientInterface) {
		err := dbc.Close()
		if err != nil {
			logger.Error("Failed to close database client", log.Error(err))
			err = fmt.Errorf("failed to close database client: %w", err)
		}
	}(dbClient)

	results, err := dbClient.ExecuteQuery(QueryGetApplicationList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	applications := make([]model.Application, 0)

	for _, row := range results {
		application, err := buildApplicationFromResultRow(row)
		if err != nil {
			logger.Error("failed to build application from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build application from result row: %w", err)
		}
		applications = append(applications, application)
	}

	return applications, nil
}

func GetApplication(id string) (model.Application, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.Application{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer dbClient.Close()

	results, err := dbClient.ExecuteQuery(QueryGetApplicationByAppId, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.Application{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("application not found")
		return model.Application{}, fmt.Errorf("application not found")
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.Application{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	application, err := buildApplicationFromResultRow(row)
	if err != nil {
		logger.Error("failed to build application from result row")
		return model.Application{}, fmt.Errorf("failed to build application from result row: %w", err)
	}
	return application, nil
}

func UpdateApplication(app *model.Application) error {

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer dbClient.Close()

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(QueryUpdateApplicationByAppId.Query, app.Id, app.Name, app.Description)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create SP application: %w", err)
	}

	_, err = tx.Exec(QueryUpdateOAuthApplicationByAppId.Query, app.Id, app.ClientId, app.ClientSecret,
		strings.Join(app.CallbackURLs, ","), strings.Join(app.SupportedGrantTypes, ","))
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create OAuth application: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func DeleteApplication(id string) error {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer dbClient.Close()

	_, err = dbClient.ExecuteQuery(QueryDeleteApplicationByAppId, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

func buildApplicationFromResultRow(row map[string]interface{}) (model.Application, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationStore"))

	appId, ok := row["app_id"].(string)
	if !ok {
		logger.Error("failed to parse app_id as string")
		return model.Application{}, fmt.Errorf("failed to parse app_id as string")
	}

	appName, ok := row["app_name"].(string)
	if !ok {
		logger.Error("failed to parse app_name as string")
		return model.Application{}, fmt.Errorf("failed to parse app_name as string")
	}

	description, ok := row["description"].(string)
	if !ok {
		logger.Error("failed to parse description as string")
		return model.Application{}, fmt.Errorf("failed to parse description as string")
	}

	clientId, ok := row["consumer_key"].(string)
	if !ok {
		logger.Error("failed to parse consumer_key as string")
		return model.Application{}, fmt.Errorf("failed to parse consumer_key as string")
	}

	var redirectURIs []string
	if row["callback_uris"] != nil {
		if uris, ok := row["callback_uris"].(string); ok {
			redirectURIs = utils.ParseStringArray(uris)
		} else {
			logger.Error("failed to parse callback_uris as string")
			return model.Application{}, fmt.Errorf("failed to parse callback_uris as string")
		}
	}

	var allowedGrantTypes []string
	if row["grant_types"] != nil {
		if grants, ok := row["grant_types"].(string); ok {
			allowedGrantTypes = utils.ParseStringArray(grants)
		} else {
			logger.Error("failed to parse grant_types as string")
			return model.Application{}, fmt.Errorf("failed to parse grant_types as string")
		}
	}

	application := model.Application{
		Id:                  appId,
		Name:                appName,
		Description:         description,
		ClientId:            clientId,
		ClientSecret:        "***",
		CallbackURLs:        redirectURIs,
		SupportedGrantTypes: allowedGrantTypes,
	}
	return application, nil
}
