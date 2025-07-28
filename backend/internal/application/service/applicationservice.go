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

// Package service provides application-related business logic and operations.
package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/application/constants"
	"github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/application/store"
	"github.com/asgardeo/thunder/internal/flow/graphservice"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/crypto/hash"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// ApplicationServiceInterface defines the interface for the application service.
type ApplicationServiceInterface interface {
	GetOAuthApplication(clientID string) (*model.OAuthApplication, error)
	CreateApplication(app *model.Application) (*model.Application, error)
	GetApplicationList() ([]model.ReturnApplication, error)
	GetApplication(appID string) (*model.ReturnApplication, error)
	UpdateApplication(appID string, app *model.Application) (*model.Application, error)
	DeleteApplication(appID string) error
}

// ApplicationService is the default implementation of the ApplicationServiceInterface.
type ApplicationService struct{}

// GetApplicationService creates a new instance of ApplicationService.
func GetApplicationService() ApplicationServiceInterface {
	return &ApplicationService{}
}

// GetOAuthApplication retrieves the OAuth application based on the client id.
func (as *ApplicationService) GetOAuthApplication(clientID string) (*model.OAuthApplication, error) {
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationService"))
	oauthApp, err := store.GetOAuthApplication(clientID)
	if err != nil {
		logger.Error("Failed to retrieve OAuth application", log.Error(err), log.String("clientID", clientID))
		return nil, err
	}

	return oauthApp, nil
}

// CreateApplication creates the application.
func (as *ApplicationService) CreateApplication(app *model.Application) (*model.Application, error) {
	if app == nil {
		return nil, errors.New("application is nil")
	}
	if app.Name == "" {
		return nil, errors.New("application name cannot be empty")
	}
	if app.ClientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if app.ClientSecret == "" {
		return nil, errors.New("client secret cannot be empty")
	}
	if len(app.CallbackURLs) == 0 {
		return nil, errors.New("at least one callback URL is required")
	}
	if err := validateAuthFlowGraphID(app); err != nil {
		return nil, err
	}
	if err := validateRegistrationFlowGraphID(app); err != nil {
		return nil, err
	}

	app.ID = utils.GenerateUUID()
	newApp := &model.Application{
		ID:                      app.ID,
		Name:                    app.Name,
		Description:             app.Description,
		ClientID:                app.ClientID,
		ClientSecret:            hash.HashString(app.ClientSecret),
		CallbackURLs:            app.CallbackURLs,
		SupportedGrantTypes:     app.SupportedGrantTypes,
		AuthFlowGraphID:         app.AuthFlowGraphID,
		RegistrationFlowGraphID: app.RegistrationFlowGraphID,
	}

	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationService"))

	// Create the application.
	err := store.CreateApplication(*newApp)
	if err != nil {
		logger.Error("Failed to create application", log.Error(err))
		return nil, err
	}

	return app, nil
}

// GetApplicationList list the applications.
func (as *ApplicationService) GetApplicationList() ([]model.ReturnApplication, error) {
	applications, err := store.GetApplicationList()
	if err != nil {
		return nil, err
	}

	return applications, nil
}

// GetApplication get the application for given app id.
func (as *ApplicationService) GetApplication(appID string) (*model.ReturnApplication, error) {
	if appID == "" {
		return nil, errors.New("application ID is empty")
	}

	application, err := store.GetApplication(appID)
	if err != nil {
		return nil, err
	}

	return &application, nil
}

// UpdateApplication update the application for given app id.
func (as *ApplicationService) UpdateApplication(appID string, app *model.Application) (*model.Application, error) {
	if appID == "" {
		return nil, errors.New("application ID is empty")
	}
	if app == nil {
		return nil, errors.New("application is nil")
	}
	if app.Name == "" {
		return nil, errors.New("application name cannot be empty")
	}
	if app.ClientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if app.ClientSecret == "" {
		return nil, errors.New("client secret cannot be empty")
	}
	if len(app.CallbackURLs) == 0 {
		return nil, errors.New("at least one callback URL is required")
	}
	if err := validateAuthFlowGraphID(app); err != nil {
		return nil, err
	}
	if err := validateRegistrationFlowGraphID(app); err != nil {
		return nil, err
	}

	newApp := &model.Application{
		ID:                      appID,
		Name:                    app.Name,
		Description:             app.Description,
		ClientID:                app.ClientID,
		ClientSecret:            hash.HashString(app.ClientSecret),
		CallbackURLs:            app.CallbackURLs,
		SupportedGrantTypes:     app.SupportedGrantTypes,
		AuthFlowGraphID:         app.AuthFlowGraphID,
		RegistrationFlowGraphID: app.RegistrationFlowGraphID,
	}

	err := store.UpdateApplication(newApp)
	if err != nil {
		return nil, err
	}

	return app, nil
}

// DeleteApplication delete the application for given app id.
func (as *ApplicationService) DeleteApplication(appID string) error {
	if appID == "" {
		return errors.New("application ID is empty")
	}

	err := store.DeleteApplication(appID)
	if err != nil {
		return err
	}

	return nil
}

// validateAuthFlowGraphID validates the auth flow graph ID for the application.
// If the graph ID is not provided, it sets the default authentication flow graph ID.
func validateAuthFlowGraphID(app *model.Application) error {
	if app.AuthFlowGraphID != "" {
		isValidFlowGraphID := graphservice.GetGraphService().IsValidGraphID(app.AuthFlowGraphID)
		if !isValidFlowGraphID {
			return fmt.Errorf("invalid auth flow graph ID: %s", app.AuthFlowGraphID)
		}
	} else {
		app.AuthFlowGraphID = getDefaultAuthFlowGraphID()
	}

	return nil
}

// validateRegistrationFlowGraphID validates the registration flow graph ID for the application.
// If the graph ID is not provided, it attempts to infer it from the auth flow graph ID.
func validateRegistrationFlowGraphID(app *model.Application) error {
	if app.RegistrationFlowGraphID != "" {
		isValidFlowGraphID := graphservice.GetGraphService().IsValidGraphID(app.RegistrationFlowGraphID)
		if !isValidFlowGraphID {
			return fmt.Errorf("invalid registration flow graph ID: %s", app.RegistrationFlowGraphID)
		}
	} else {
		if strings.HasPrefix(app.AuthFlowGraphID, constants.AuthFlowGraphPrefix) {
			suffix := strings.TrimPrefix(app.AuthFlowGraphID, constants.AuthFlowGraphPrefix)
			app.RegistrationFlowGraphID = constants.RegistrationFlowGraphPrefix + suffix
		} else {
			return fmt.Errorf("cannot infer registration flow graph ID from auth flow graph ID: %s",
				app.AuthFlowGraphID)
		}
	}

	return nil
}

// getDefaultAuthFlowGraphID returns the configured default authentication flow graph ID.
func getDefaultAuthFlowGraphID() string {
	authFlowConfig := config.GetThunderRuntime().Config.Flow.Authn
	return authFlowConfig.DefaultFlow
}
