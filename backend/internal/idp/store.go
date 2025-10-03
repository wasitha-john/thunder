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

package idp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/system/cmodels"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// idpStoreInterface defines the interface for identity provider store operations.
type idpStoreInterface interface {
	CreateIdentityProvider(idp IDPDTO) error
	GetIdentityProviderList() ([]BasicIDPDTO, error)
	GetIdentityProvider(idpID string) (*IDPDTO, error)
	GetIdentityProviderByName(idpName string) (*IDPDTO, error)
	UpdateIdentityProvider(idp *IDPDTO) error
	DeleteIdentityProvider(idpID string) error
}

// idpStore is the default implementation of IDPStoreInterface.
type idpStore struct {
	dbProvider provider.DBProviderInterface
}

// newIDPStore creates a new instance of IDPStore.
func newIDPStore() idpStoreInterface {
	return &idpStore{
		dbProvider: provider.GetDBProvider(),
	}
}

// CreateIdentityProvider handles the IdP creation in the database.
func (s *idpStore) CreateIdentityProvider(idp IDPDTO) error {
	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	_, err = tx.Exec(queryCreateIdentityProvider.Query, idp.ID, idp.Name, idp.Description, idp.Type)
	if err != nil {
		retErr := fmt.Errorf("failed to execute query: %w", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return retErr
	}

	if len(idp.Properties) > 0 {
		queryValues := make([]string, 0, len(idp.Properties))
		for _, property := range idp.Properties {
			if property.GetName() != "" {
				propertyValue := property.GetStorageValue()
				queryValues = append(queryValues, fmt.Sprintf("('%s', '%s', '%s', '%s', '%s')",
					idp.ID, property.GetName(), propertyValue,
					sysutils.BoolToNumString(property.IsSecret()),
					sysutils.BoolToNumString(property.IsEncrypted())))
			} else {
				return fmt.Errorf("property name cannot be empty")
			}
		}

		propertyInsertQuery := queryInsertIDPProperties
		propertyInsertQuery.Query = fmt.Sprintf(propertyInsertQuery.Query, strings.Join(queryValues, ", "))

		_, err = tx.Exec(propertyInsertQuery.Query)
		if err != nil {
			retErr := fmt.Errorf("failed to execute query for inserting properties: %w", err)
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
			}
			return retErr
		}
	}

	if err = tx.Commit(); err != nil {
		retErr := fmt.Errorf("failed to commit transaction: %w", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return retErr
	}

	return nil
}

// GetIdentityProviderList retrieves a list of IdPs from the database.
func (s *idpStore) GetIdentityProviderList() ([]BasicIDPDTO, error) {
	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}

	results, err := dbClient.Query(queryGetIdentityProviderList)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	idpList := make([]BasicIDPDTO, 0)
	for _, row := range results {
		idp, err := buildIDPFromResultRow(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build idp from result row: %w", err)
		}
		idpList = append(idpList, *idp)
	}

	return idpList, nil
}

// getIDPProperties retrieves the properties of a specific IdP by its ID.
func (s *idpStore) getIDPProperties(idpID string) ([]cmodels.Property, error) {
	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}

	results, err := dbClient.Query(queryGetIDPProperties, idpID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return buildIDPPropertiesFromResultSet(results)
}

// GetIdentityProvider retrieves a specific idp by its ID from the database.
func (s *idpStore) GetIdentityProvider(id string) (*IDPDTO, error) {
	return s.getIDP(queryGetIdentityProviderByID, id)
}

// GetIdentityProviderByName retrieves a specific idp by its name from the database.
func (s *idpStore) GetIdentityProviderByName(name string) (*IDPDTO, error) {
	return s.getIDP(queryGetIdentityProviderByName, name)
}

// getIDP retrieves an IDP based on the provided query and identifier.
func (s *idpStore) getIDP(query dbmodel.DBQuery, identifier string) (*IDPDTO, error) {
	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}

	results, err := dbClient.Query(query, identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrIDPNotFound
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	basicIDP, err := buildIDPFromResultRow(row)
	if err != nil {
		return nil, fmt.Errorf("failed to build idp from result row: %w", err)
	}

	idp := &IDPDTO{
		ID:          basicIDP.ID,
		Name:        basicIDP.Name,
		Description: basicIDP.Description,
		Type:        basicIDP.Type,
	}

	// Retrieve properties for the IdP
	properties, err := s.getIDPProperties(idp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get idp properties: %w", err)
	}
	idp.Properties = properties

	return idp, nil
}

// UpdateIdentityProvider updates the idp in the database.
func (s *idpStore) UpdateIdentityProvider(idp *IDPDTO) error {
	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}

	tx, err := dbClient.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Update the IDP in the database
	if _, err := tx.Exec(queryUpdateIdentityProviderByID.Query, idp.ID, idp.Name,
		idp.Description, idp.Type); err != nil {
		retErr := fmt.Errorf("failed to execute query: %w", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return retErr
	}

	// delete existing properties for the IdP
	if _, err := tx.Exec(queryDeleteIDPProperties.Query, idp.ID); err != nil {
		retErr := fmt.Errorf("failed to execute query for deleting existing properties: %w", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return retErr
	}

	// If properties are provided, insert them into the database.
	if len(idp.Properties) > 0 {
		queryValues := make([]string, 0, len(idp.Properties))
		for _, property := range idp.Properties {
			if property.GetName() != "" {
				propertyValue := property.GetStorageValue()
				queryValues = append(queryValues, fmt.Sprintf("('%s', '%s', '%s', '%s', '%s')",
					idp.ID, property.GetName(), propertyValue,
					sysutils.BoolToNumString(property.IsSecret()),
					sysutils.BoolToNumString(property.IsEncrypted())))
			} else {
				return fmt.Errorf("property name cannot be empty")
			}
		}

		// Insert new properties for the IdP
		propertyInsertQuery := queryInsertIDPProperties
		propertyInsertQuery.Query = fmt.Sprintf(propertyInsertQuery.Query, strings.Join(queryValues, ", "))
		if _, err := tx.Exec(propertyInsertQuery.Query); err != nil {
			retErr := fmt.Errorf("failed to execute query for inserting properties: %w", err)
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
			}
			return retErr
		}
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		retErr := fmt.Errorf("failed to commit transaction: %w", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to rollback transaction: %w", rollbackErr))
		}
		return retErr
	}

	return nil
}

// DeleteIdentityProvider deletes the idp from the database.
func (s *idpStore) DeleteIdentityProvider(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := s.dbProvider.GetDBClient("identity")
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}

	rowsAffected, err := dbClient.Execute(queryDeleteIdentityProviderByID, id)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}
	if rowsAffected == 0 {
		logger.Debug("idp not found with id: " + id)
	}

	return nil
}

func buildIDPFromResultRow(row map[string]interface{}) (*BasicIDPDTO, error) {
	idpID, ok := row["idp_id"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse idp_id as string")
	}

	idpName, ok := row["name"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse name as string")
	}

	idpDescription, ok := row["description"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse description as string")
	}

	idpType, ok := row["type"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse type as string")
	}

	idp := BasicIDPDTO{
		ID:          idpID,
		Name:        idpName,
		Description: idpDescription,
		Type:        IDPType(idpType),
	}

	return &idp, nil
}

// buildIDPPropertiesFromResultSet builds a slice of IDPProperty from the result set.
func buildIDPPropertiesFromResultSet(results []map[string]interface{}) ([]cmodels.Property, error) {
	properties := make([]cmodels.Property, 0, len(results))

	for _, row := range results {
		propertyName, ok := row["property_name"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse property_name as string")
		}

		propertyValue, ok := row["property_value"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse property_value as string")
		}

		isSecretStr, ok := row["is_secret"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse is_secret as string")
		}
		isSecret := sysutils.NumStringToBool(isSecretStr)

		isEncryptedStr, ok := row["is_encrypted"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse is_encrypted as string")
		}
		isEncrypted := sysutils.NumStringToBool(isEncryptedStr)

		property := cmodels.NewRawProperty(propertyName, propertyValue, isSecret, isEncrypted)
		properties = append(properties, *property)
	}

	return properties, nil
}
