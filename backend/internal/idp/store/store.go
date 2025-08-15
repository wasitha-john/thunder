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

// Package store provides the implementation for identity provider persistence operations.
package store

import (
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/idp/model"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// CreateIdentityProvider handles the IdP creation in the database.
func CreateIdentityProvider(idp model.IDP) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(QueryCreateIdentityProvider.Query, idp.ID, idp.Name, idp.Description)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if len(idp.Properties) > 0 {
		queryValues := make([]string, 0, len(idp.Properties))
		for _, property := range idp.Properties {
			if property.Name != "" {
				queryValues = append(queryValues, fmt.Sprintf("('%s', '%s', '%s', '%s')",
					idp.ID, property.Name, property.Value, sysutils.BoolToNumString(property.IsSecret)))
			} else {
				logger.Error("Property name cannot be empty")
				return fmt.Errorf("property name cannot be empty")
			}
		}

		propertyInsertQuery := QueryInsertIDPProperties
		propertyInsertQuery.Query = fmt.Sprintf(propertyInsertQuery.Query, strings.Join(queryValues, ", "))

		_, err = tx.Exec(propertyInsertQuery.Query)
		if err != nil {
			logger.Error("Failed to execute query for inserting properties", log.Error(err))
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
				return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
			}
			return fmt.Errorf("failed to execute query for inserting properties: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetIdentityProviderList retrieves a list of IdP from the database.
func GetIdentityProviderList() ([]model.IDP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetIdentityProviderList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	idps := make([]model.IDP, 0)

	for _, row := range results {
		idp, err := buildIDPFromResultRow(row)
		if err != nil {
			logger.Error("failed to build idp from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build idp from result row: %w", err)
		}

		// Retrieve properties for the IdP
		properties, err := GetIDPProperties(idp.ID)
		if err != nil {
			logger.Error("failed to get idp properties", log.Error(err))
			return nil, fmt.Errorf("failed to get idp properties: %w", err)
		}
		idp.Properties = properties

		idps = append(idps, idp)
	}

	return idps, nil
}

// GetIDPProperties retrieves the properties of a specific IdP by its ID.
func GetIDPProperties(idpID string) ([]model.IDPProperty, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetIDPProperties, idpID)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return buildIDPPropertiesFromResultSet(results)
}

// GetIdentityProvider retrieves a specific idp by its ID from the database.
func GetIdentityProvider(id string) (model.IDP, error) {
	return getIDP(QueryGetIdentityProviderByID, id)
}

// GetIdentityProviderByName retrieves a specific idp by its name from the database.
func GetIdentityProviderByName(name string) (model.IDP, error) {
	return getIDP(QueryGetIdentityProviderByName, name)
}

// getIDP retrieves an IDP based on the provided query and identifier.
func getIDP(query dbmodel.DBQuery, identifier string) (model.IDP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.IDP{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(query, identifier)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.IDP{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("idp not found with the provided identifier: " + identifier)
		return model.IDP{}, model.ErrIDPNotFound
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.IDP{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	idp, err := buildIDPFromResultRow(row)
	if err != nil {
		logger.Error("failed to build idp from result row")
		return model.IDP{}, fmt.Errorf("failed to build idp from result row: %w", err)
	}

	// Retrieve properties for the IdP
	properties, err := GetIDPProperties(idp.ID)
	if err != nil {
		logger.Error("failed to get idp properties", log.Error(err))
		return model.IDP{}, fmt.Errorf("failed to get idp properties: %w", err)
	}
	idp.Properties = properties

	return idp, nil
}

// UpdateIdentityProvider updates the idp in the database.
func UpdateIdentityProvider(idp *model.IDP) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Update the IDP in the database
	if _, err := tx.Exec(QueryUpdateIdentityProviderByID.Query, idp.ID, idp.Name, idp.Description); err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return fmt.Errorf("failed to execute query: %w", err)
	}

	// delete existing properties for the IdP
	if _, err := tx.Exec(QueryDeleteIDPProperties.Query, idp.ID); err != nil {
		logger.Error("Failed to execute query for deleting existing properties", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return fmt.Errorf("failed to execute query for deleting existing properties: %w", err)
	}

	// If properties are provided, insert them into the database.
	if len(idp.Properties) > 0 {
		queryValues := make([]string, 0, len(idp.Properties))
		for _, property := range idp.Properties {
			if property.Name != "" {
				queryValues = append(queryValues, fmt.Sprintf("('%s', '%s', '%s', '%s')",
					idp.ID, property.Name, property.Value, sysutils.BoolToNumString(property.IsSecret)))
			} else {
				logger.Error("Property name cannot be empty")
				return fmt.Errorf("property name cannot be empty")
			}
		}

		// Insert new properties for the IdP
		propertyInsertQuery := QueryInsertIDPProperties
		propertyInsertQuery.Query = fmt.Sprintf(propertyInsertQuery.Query, strings.Join(queryValues, ", "))
		if _, err := tx.Exec(propertyInsertQuery.Query); err != nil {
			logger.Error("Failed to execute query for inserting properties", log.Error(err))
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
				return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
			}
			return fmt.Errorf("failed to execute query for inserting properties: %w", err)
		}
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", log.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
			return fmt.Errorf("failed to rollback transaction: %w", rollbackErr)
		}
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteIdentityProvider deletes the idp from the database.
func DeleteIdentityProvider(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	rowsAffected, err := dbClient.Execute(QueryDeleteIdentityProviderByID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("idp not found with id: " + id)
	}

	return nil
}

func buildIDPFromResultRow(row map[string]interface{}) (model.IDP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	idpID, ok := row["idp_id"].(string)
	if !ok {
		logger.Error("failed to parse idp_id as string")
		return model.IDP{}, fmt.Errorf("failed to parse idp_id as string")
	}

	idpName, ok := row["name"].(string)
	if !ok {
		logger.Error("failed to parse name as string")
		return model.IDP{}, fmt.Errorf("failed to parse name as string")
	}

	idpDescription, ok := row["description"].(string)
	if !ok {
		logger.Error("failed to parse description as string")
		return model.IDP{}, fmt.Errorf("failed to parse description as string")
	}

	idp := model.IDP{
		ID:          idpID,
		Name:        idpName,
		Description: idpDescription,
	}

	return idp, nil
}

// buildIDPPropertiesFromResultSet builds a slice of IDPProperty from the result set.
func buildIDPPropertiesFromResultSet(results []map[string]interface{}) ([]model.IDPProperty, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	properties := make([]model.IDPProperty, 0, len(results))

	for _, row := range results {
		propertyName, ok := row["property_name"].(string)
		if !ok {
			logger.Error("failed to parse property_name as string")
			return nil, fmt.Errorf("failed to parse property_name as string")
		}

		propertyValue, ok := row["property_value"].(string)
		if !ok {
			logger.Error("failed to parse property_value as string")
			return nil, fmt.Errorf("failed to parse property_value as string")
		}

		isSecretStr, ok := row["is_secret"].(string)
		if !ok {
			logger.Error("failed to parse is_secret as string")
			return nil, fmt.Errorf("failed to parse is_secret as string")
		}
		isSecret := sysutils.NumStringToBool(isSecretStr)

		property := model.IDPProperty{
			Name:     propertyName,
			Value:    propertyValue,
			IsSecret: isSecret,
		}
		properties = append(properties, property)
	}

	return properties, nil
}
