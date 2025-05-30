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

// Package store provides the implementation for identity provider persistence operations.
package store

import (
	"encoding/json"
	"fmt"

	"github.com/asgardeo/thunder/internal/idp/model"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
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

	// Convert scopes to JSON string
	scopes, err := json.Marshal(idp.Scopes)
	if err != nil {
		logger.Error("Failed to marshal scopes", log.Error(err))
		return model.ErrBadScopesInRequest
	}

	_, err = dbClient.Execute(QueryCreateIdentityProvider, idp.ID, idp.Name, idp.Description, idp.ClientID,
		idp.ClientSecret, idp.RedirectURI, string(scopes))
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
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
		idp, err := buildIDPForListFromResultRow(row)
		if err != nil {
			logger.Error("failed to build idp from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build idp from result row: %w", err)
		}
		idps = append(idps, idp)
	}

	return idps, nil
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

	// Convert scopes to JSON string
	scopes, err := json.Marshal(idp.Scopes)
	if err != nil {
		logger.Error("Failed to marshal scopes", log.Error(err))
		return model.ErrBadScopesInRequest
	}

	rowsAffected, err := dbClient.Execute(QueryUpdateIdentityProviderByID, idp.ID, idp.Name, idp.Description,
		idp.ClientID, idp.ClientSecret, idp.RedirectURI, string(scopes))
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("idp not found with id: " + idp.ID)
		return model.ErrIDPNotFound
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

	idpClientID, ok := row["client_id"].(string)
	if !ok {
		logger.Error("failed to parse client_id as string")
		return model.IDP{}, fmt.Errorf("failed to parse client_id as string")
	}

	idpClientSecret, ok := row["client_secret"].(string)
	if !ok {
		logger.Error("failed to parse client_secret as string")
		return model.IDP{}, fmt.Errorf("failed to parse client_secret as string")
	}

	idpRedirectURI, ok := row["redirect_uri"].(string)
	if !ok {
		logger.Error("failed to parse redirect_uri as string")
		return model.IDP{}, fmt.Errorf("failed to parse redirect_uri as string")
	}

	var scopes string
	switch v := row["scopes"].(type) {
	case string:
		scopes = v
	case []byte:
		scopes = string(v) // Convert byte slice to string
	default:
		logger.Error("failed to parse scopes", log.Any("raw_value", row["scopes"]), log.String("type",
			fmt.Sprintf("%T", row["scopes"])))
		return model.IDP{}, fmt.Errorf("failed to parse scopes as string")
	}

	idp := model.IDP{
		ID:           idpID,
		Name:         idpName,
		Description:  idpDescription,
		ClientID:     idpClientID,
		ClientSecret: idpClientSecret,
		RedirectURI:  idpRedirectURI,
	}

	// Unmarshal JSON scopes
	if err := json.Unmarshal([]byte(scopes), &idp.Scopes); err != nil {
		logger.Error("Failed to unmarshal scopes")
		return model.IDP{}, fmt.Errorf("failed to unmarshal scopes")
	}

	return idp, nil
}

func buildIDPForListFromResultRow(row map[string]interface{}) (model.IDP, error) {
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

	idpClientID, ok := row["client_id"].(string)
	if !ok {
		logger.Error("failed to parse client_id as string")
		return model.IDP{}, fmt.Errorf("failed to parse client_id as string")
	}

	var scopes string
	switch v := row["scopes"].(type) {
	case string:
		scopes = v
	case []byte:
		scopes = string(v) // Convert byte slice to string
	default:
		logger.Error("failed to parse scopes", log.Any("raw_value", row["scopes"]), log.String("type",
			fmt.Sprintf("%T", row["scopes"])))
		return model.IDP{}, fmt.Errorf("failed to parse scopes as string")
	}

	idp := model.IDP{
		ID:          idpID,
		Name:        idpName,
		Description: idpDescription,
		ClientID:    idpClientID,
	}

	// Unmarshal JSON scopes
	if err := json.Unmarshal([]byte(scopes), &idp.Scopes); err != nil {
		logger.Error("Failed to unmarshal scopes")
		return model.IDP{}, fmt.Errorf("failed to unmarshal scopes")
	}

	return idp, nil
}
