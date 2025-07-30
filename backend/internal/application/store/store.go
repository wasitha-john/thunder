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

// Package store provides functionality for handling application data persistence.
package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/application/constants"
	"github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/system/database/client"
	dbmodel "github.com/asgardeo/thunder/internal/system/database/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// ApplicationStoreInterface defines the interface for application data persistence operations.
type ApplicationStoreInterface interface {
	CreateApplication(app model.ApplicationProcessedDTO) error
	GetApplicationList() ([]model.ApplicationProcessedDTO, error)
	GetApplication(id string) (model.ApplicationProcessedDTO, error)
	GetOAuthApplication(clientID string) (*model.OAuthAppConfigProcessed, error)
	UpdateApplication(app *model.ApplicationProcessedDTO) error
	DeleteApplication(id string) error
}

// ApplicationStore implements the ApplicationStoreInterface for handling application data persistence.
type ApplicationStore struct{}

// NewApplicationStore creates a new instance of ApplicationStore.
func NewApplicationStore() ApplicationStoreInterface {
	return &ApplicationStore{}
}

// CreateApplication creates a new application in the database.
func (st *ApplicationStore) CreateApplication(app model.ApplicationProcessedDTO) error {
	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	inboundAuthConfig := app.InboundAuthConfig[0]
	callBackURIs, grantTypes := getCallbackURIsAndGrantTypes(inboundAuthConfig)

	queries := []func(tx dbmodel.TxInterface) error{
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryCreateApplication.Query, app.ID, app.Name, app.Description, app.AuthFlowGraphID,
				app.RegistrationFlowGraphID, app.IsRegistrationFlowEnabled, app.URL, app.LogoURL)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryCreateOAuthApplication.Query, app.ID, inboundAuthConfig.OAuthAppConfig.ClientID,
				inboundAuthConfig.OAuthAppConfig.HashedClientSecret, callBackURIs, grantTypes)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			if len(app.Properties) > 0 {
				query := prepareApplicationPropertyInsertQuery(app.ID, app.Properties)
				_, err := tx.Exec(query.Query)
				return err
			}
			return nil
		},
		func(tx dbmodel.TxInterface) error {
			if app.Certificate != nil && app.Certificate.Type != constants.CertificateTypeNone {
				_, err := tx.Exec(QueryInsertApplicationCertificate.Query, app.ID, app.Certificate.Type,
					app.Certificate.Value)
				return err
			}
			return nil
		},
	}

	return executeTransaction(queries)
}

// GetApplicationList retrieves a list of applications from the database.
func (st *ApplicationStore) GetApplicationList() ([]model.ApplicationProcessedDTO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func(dbc client.DBClientInterface) {
		err := dbc.Close()
		if err != nil {
			logger.Error("Failed to close database client", log.Error(err))
		}
	}(dbClient)

	results, err := dbClient.Query(QueryGetApplicationList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	applications := make([]model.ApplicationProcessedDTO, 0)

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

// GetApplication retrieves a specific application by its ID from the database.
func (st *ApplicationStore) GetApplication(id string) (model.ApplicationProcessedDTO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetApplicationByAppID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("application not found")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("application not found")
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	application, err := buildApplicationFromResultRow(row)
	if err != nil {
		logger.Error("failed to build application from result row")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to build application from result row: %w", err)
	}

	// Retrieve application properties.
	properties, err := GetApplicationProperties(application.ID)
	if err != nil {
		logger.Error("failed to get application properties", log.Error(err))
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to get application properties: %w", err)
	}
	application.Properties = properties

	// Retrieve application certificate.
	certificate, err := GetApplicationCertificate(application.ID)
	if err != nil {
		logger.Error("failed to get application certificate", log.Error(err))
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to get application certificate: %w", err)
	}
	application.Certificate = certificate

	return application, nil
}

// GetOAuthApplication retrieves an OAuth application by its client ID.
func (st *ApplicationStore) GetOAuthApplication(clientID string) (*model.OAuthAppConfigProcessed, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

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

	results, err := dbClient.Query(QueryGetOAuthApplicationByClientID, clientID)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("OAuth application not found")
	}

	row := results[0]

	appID, ok := row["app_id"].(string)
	if !ok {
		return nil, errors.New("failed to parse app_id as string")
	}

	hashedClientSecret, ok := row["consumer_secret"].(string)
	if !ok {
		return nil, errors.New("failed to parse consumer_secret as string")
	}

	var redirectURIs []string
	if row["callback_uris"] != nil {
		if uris, ok := row["callback_uris"].(string); ok {
			redirectURIs = utils.ParseStringArray(uris, ",")
		} else {
			return nil, errors.New("failed to parse callback_uris as string")
		}
	}

	var grantTypes []string
	if row["grant_types"] != nil {
		if grants, ok := row["grant_types"].(string); ok {
			grantTypes = utils.ParseStringArray(grants, ",")
		} else {
			return nil, errors.New("failed to parse grant_types as string")
		}
	}

	return &model.OAuthAppConfigProcessed{
		AppID:              appID,
		ClientID:           clientID,
		HashedClientSecret: hashedClientSecret,
		RedirectURIs:       redirectURIs,
		GrantTypes:         grantTypes,
	}, nil
}

// GetApplicationProperties retrieves the properties of an application by its ID.
func GetApplicationProperties(appID string) ([]model.ApplicationProperty, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

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

	results, err := dbClient.Query(QueryGetApplicationProperties, appID)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return buildApplicationPropertiesFromResultSet(results)
}

// GetApplicationCertificate retrieves the certificate of an application by its ID.
func GetApplicationCertificate(appID string) (*model.Certificate, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

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

	results, err := dbClient.Query(QueryGetApplicationCertificate, appID)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		return &model.Certificate{
			Type:  constants.CertificateTypeNone,
			Value: "",
		}, nil
	}

	row := results[0]
	certificate := &model.Certificate{
		Type:  constants.CertificateType(row["certificate_type"].(string)),
		Value: row["certificate_value"].(string),
	}

	return certificate, nil
}

// UpdateApplication updates an existing application in the database.
func (st *ApplicationStore) UpdateApplication(app *model.ApplicationProcessedDTO) error {
	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	inboundAuthConfig := app.InboundAuthConfig[0]
	callBackURIs, grantTypes := getCallbackURIsAndGrantTypes(inboundAuthConfig)

	queries := []func(tx dbmodel.TxInterface) error{
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryUpdateApplicationByAppID.Query, app.ID, app.Name, app.Description,
				app.AuthFlowGraphID, app.RegistrationFlowGraphID, app.IsRegistrationFlowEnabled,
				app.URL, app.LogoURL)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryUpdateOAuthApplicationByAppID.Query, app.ID,
				inboundAuthConfig.OAuthAppConfig.ClientID, inboundAuthConfig.OAuthAppConfig.HashedClientSecret,
				callBackURIs, grantTypes)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			_, err := tx.Exec(QueryDeleteApplicationProperties.Query, app.ID)
			return err
		},
		func(tx dbmodel.TxInterface) error {
			if len(app.Properties) > 0 {
				query := prepareApplicationPropertyInsertQuery(app.ID, app.Properties)
				_, err := tx.Exec(query.Query)
				return err
			}
			return nil
		},
		func(tx dbmodel.TxInterface) error {
			if app.Certificate == nil || app.Certificate.Type == constants.CertificateTypeNone {
				_, err := tx.Exec(QueryDeleteApplicationCertificate.Query, app.ID)
				return err
			} else {
				_, err := tx.Exec(QueryUpdateApplicationCertificate.Query, app.ID, app.Certificate.Type,
					app.Certificate.Value)
				return err
			}
		},
	}

	return executeTransaction(queries)
}

// DeleteApplication deletes an application from the database by its ID.
func (st *ApplicationStore) DeleteApplication(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

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

	_, err = dbClient.Execute(QueryDeleteApplicationByAppID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// getCallbackURIsAndGrantTypes extracts callback URIs and grant types from the inbound auth configuration.
func getCallbackURIsAndGrantTypes(inboundAuthConfig model.InboundAuthConfigProcessed) (string, string) {
	callBackURIs := ""
	if len(inboundAuthConfig.OAuthAppConfig.RedirectURIs) > 0 {
		callBackURIs = strings.Join(inboundAuthConfig.OAuthAppConfig.RedirectURIs, ",")
	}
	grantTypes := ""
	if len(inboundAuthConfig.OAuthAppConfig.GrantTypes) > 0 {
		grantTypes = strings.Join(inboundAuthConfig.OAuthAppConfig.GrantTypes, ",")
	}
	return callBackURIs, grantTypes
}

// buildApplicationFromResultRow constructs an Application object from a database result row.
func buildApplicationFromResultRow(row map[string]interface{}) (model.ApplicationProcessedDTO, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

	appID, ok := row["app_id"].(string)
	if !ok {
		logger.Error("failed to parse app_id as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse app_id as string")
	}

	appName, ok := row["app_name"].(string)
	if !ok {
		logger.Error("failed to parse app_name as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse app_name as string")
	}

	var description string
	if row["description"] == nil {
		description = ""
	} else if desc, ok := row["description"].(string); ok {
		description = desc
	} else {
		logger.Error("failed to parse description as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse description as string")
	}

	authFlowGraphID, ok := row["auth_flow_graph_id"].(string)
	if !ok {
		logger.Error("failed to parse auth_flow_graph_id as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse auth_flow_graph_id as string")
	}

	regisFlowGraphID, ok := row["registration_flow_graph_id"].(string)
	if !ok {
		logger.Error("failed to parse registration_flow_graph_id as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse registration_flow_graph_id as string")
	}

	isRegistrationFlowEnabledStr, ok := row["is_registration_flow_enabled"].(string)
	if !ok {
		logger.Error("failed to parse is_registration_flow_enabled as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse is_registration_flow_enabled as string")
	}
	isRegistrationFlowEnabled := sysutils.NumStringToBool(isRegistrationFlowEnabledStr)

	var url string
	if row["url"] == nil {
		url = ""
	} else if u, ok := row["url"].(string); ok {
		url = u
	} else {
		logger.Error("failed to parse url as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse url as string")
	}

	var logoURL string
	if row["logo_url"] == nil {
		logoURL = ""
	} else if l, ok := row["logo_url"].(string); ok {
		logoURL = l
	} else {
		logger.Error("failed to parse logo_url as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse logo_url as string")
	}

	clientID, ok := row["consumer_key"].(string)
	if !ok {
		logger.Error("failed to parse consumer_key as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse consumer_key as string")
	}

	hashedClientSecret, ok := row["consumer_secret"].(string)
	if !ok {
		logger.Error("failed to parse consumer_secret as string")
		return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse consumer_secret as string")
	}

	var redirectURIs []string
	if row["callback_uris"] != nil {
		if uris, ok := row["callback_uris"].(string); ok {
			redirectURIs = utils.ParseStringArray(uris, ",")
		} else {
			logger.Error("failed to parse callback_uris as string")
			return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse callback_uris as string")
		}
	}

	var grantTypes []string
	if row["grant_types"] != nil {
		if grants, ok := row["grant_types"].(string); ok {
			grantTypes = utils.ParseStringArray(grants, ",")
		} else {
			logger.Error("failed to parse grant_types as string")
			return model.ApplicationProcessedDTO{}, fmt.Errorf("failed to parse grant_types as string")
		}
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	inboundAuthConfig := model.InboundAuthConfigProcessed{
		Type: constants.OAuthInboundAuthType,
		OAuthAppConfig: &model.OAuthAppConfigProcessed{
			AppID:              appID,
			ClientID:           clientID,
			HashedClientSecret: hashedClientSecret,
			RedirectURIs:       redirectURIs,
			GrantTypes:         grantTypes,
		},
	}
	application := model.ApplicationProcessedDTO{
		ID:                        appID,
		Name:                      appName,
		Description:               description,
		AuthFlowGraphID:           authFlowGraphID,
		RegistrationFlowGraphID:   regisFlowGraphID,
		IsRegistrationFlowEnabled: isRegistrationFlowEnabled,
		URL:                       url,
		LogoURL:                   logoURL,
		InboundAuthConfig:         []model.InboundAuthConfigProcessed{inboundAuthConfig},
	}

	return application, nil
}

// buildApplicationPropertiesFromResultSet constructs a slice of ApplicationProperty from the result set.
func buildApplicationPropertiesFromResultSet(results []map[string]interface{}) ([]model.ApplicationProperty, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

	properties := make([]model.ApplicationProperty, 0)

	for _, row := range results {
		propertyName, ok := row["property_name"].(string)
		if !ok {
			logger.Error("failed to parse property_name as string")
			return nil, fmt.Errorf("failed to parse property_name as string")
		}

		var propertyValue string
		if row["property_value"] == nil {
			propertyValue = ""
		} else if value, ok := row["property_value"].(string); ok {
			propertyValue = value
		} else {
			logger.Error("failed to parse property_value as string")
			return nil, fmt.Errorf("failed to parse property_value as string")
		}

		isSecretStr, ok := row["is_secret"].(string)
		if !ok {
			logger.Error("failed to parse is_secret as string")
			return nil, fmt.Errorf("failed to parse is_secret as string")
		}
		isSecret := sysutils.NumStringToBool(isSecretStr)

		property := model.ApplicationProperty{
			Name:     propertyName,
			Value:    propertyValue,
			IsSecret: isSecret,
		}
		properties = append(properties, property)
	}

	return properties, nil
}

// executeTransaction is a helper function to handle database transactions.
func executeTransaction(queries []func(tx dbmodel.TxInterface) error) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
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

	for _, query := range queries {
		if err := query(tx); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Error("Failed to rollback transaction", log.Error(rollbackErr))
				err = errors.Join(err, errors.New("failed to rollback transaction: "+rollbackErr.Error()))
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// prepareApplicationPropertyInsertQuery prepares the query for inserting application properties.
func prepareApplicationPropertyInsertQuery(appID string, appProperties []model.ApplicationProperty) dbmodel.DBQuery {
	var values []string
	for _, prop := range appProperties {
		values = append(values, fmt.Sprintf("('%s', '%s', '%s', %s)", appID, prop.Name, prop.Value,
			sysutils.BoolToNumString(prop.IsSecret)))
	}
	insertQuery := QueryInsertApplicationProperties
	insertQuery.Query = fmt.Sprintf(insertQuery.Query, strings.Join(values, ", "))
	return insertQuery
}
