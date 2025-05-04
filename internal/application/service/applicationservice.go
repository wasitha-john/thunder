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

package service

import (
	"errors"
	"github.com/asgardeo/thunder/internal/application/store"
	"github.com/google/uuid"

	"github.com/asgardeo/thunder/internal/application/model"
	dbprovider "github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/utils"
)

// ApplicationServiceInterface defines the interface for the application service.
type ApplicationServiceInterface interface {
	GetOAuthApplication(clientId string) (*model.OAuthApplication, error)
	CreateApplication(app *model.Application) (*model.Application, error)
	GetApplicationList() ([]model.Application, error)
	GetApplication(appId string) (*model.Application, error)
	UpdateApplication(appId string, app *model.Application) (*model.Application, error)
	DeleteApplication(appId string) error
}

// ApplicationService is the default implementation of the ApplicationServiceInterface.
type ApplicationService struct{}

// GetApplicationService creates a new instance of ApplicationService.
func GetApplicationService() ApplicationServiceInterface {

	return &ApplicationService{}
}

// GetOAuthApplication retrieves the OAuth application based on the client id.
func (as *ApplicationService) GetOAuthApplication(clientId string) (*model.OAuthApplication, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationService"))

	if clientId == "" {
		return nil, errors.New("client ID cannot be empty")
	}

	dbClient, err := dbprovider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, err
	}
	defer dbClient.Close()

	results, err := dbClient.ExecuteQuery(store.QueryGetApplicationByClientId, clientId)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("OAuth application not found")
	}

	row := results[0]

	clientId, ok := row["consumer_key"].(string)
	if !ok {
		return nil, errors.New("failed to parse consumer_key as string")
	}

	clientSecret, ok := row["consumer_secret"].(string)
	if !ok {
		return nil, errors.New("failed to parse consumer_secret as string")
	}

	var redirectURIs []string
	if row["callback_uris"] != nil {
		if uris, ok := row["callback_uris"].(string); ok {
			redirectURIs = utils.ParseStringArray(uris)
		} else {
			return nil, errors.New("failed to parse callback_uris as string")
		}
	}

	var allowedGrantTypes []string
	if row["grant_types"] != nil {
		if grants, ok := row["grant_types"].(string); ok {
			allowedGrantTypes = utils.ParseStringArray(grants)
		} else {
			return nil, errors.New("failed to parse grant_types as string")
		}
	}

	return &model.OAuthApplication{
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		RedirectURIs:      redirectURIs,
		AllowedGrantTypes: allowedGrantTypes,
	}, nil
}

// CreateApplication creates the application.
func (as *ApplicationService) CreateApplication(app *model.Application) (*model.Application, error) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "ApplicationService"))

	app.Id = uuid.New().String()

	// Create the application in the database.
	err := store.CreateApplication(*app)
	if err != nil {
		logger.Error("Failed to create application", log.Error(err))
		return nil, err
	}
	return app, nil
}

// GetApplicationList list the applications.
func (as *ApplicationService) GetApplicationList() ([]model.Application, error) {

	applications, err := store.GetApplicationList()
	if err != nil {
		return nil, err
	}

	return applications, nil
}

// GetApplication get the application for given app id.
func (as *ApplicationService) GetApplication(appId string) (*model.Application, error) {

	if appId == "" {
		return nil, errors.New("application ID is empty")
	}

	application, err := store.GetApplication(appId)
	if err != nil {
		return nil, err
	}

	return &application, nil
}

// UpdateApplication update the application for given app id.
func (as *ApplicationService) UpdateApplication(appId string, app *model.Application) (*model.Application, error) {

	if appId == "" {
		return nil, errors.New("application ID is empty")
	}

	err := store.UpdateApplication(app)
	if err != nil {
		return nil, err
	}

	return app, nil
}

// DeleteApplication delete the application for given app id.
func (as *ApplicationService) DeleteApplication(appId string) error {

	if appId == "" {
		return errors.New("application ID is empty")
	}

	err := store.DeleteApplication(appId)
	if err != nil {
		return err
	}

	return nil
}
