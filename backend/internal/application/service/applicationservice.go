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
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// ApplicationServiceInterface defines the interface for the application service.
type ApplicationServiceInterface interface {
	GetOAuthApplication(clientID string) (*model.OAuthAppConfigProcessed, error)
	CreateApplication(app *model.ApplicationDTO) (*model.ApplicationDTO, error)
	GetApplicationList() ([]model.BasicApplicationDTO, error)
	GetApplication(appID string) (*model.ApplicationProcessedDTO, error)
	UpdateApplication(appID string, app *model.ApplicationDTO) (*model.ApplicationDTO, error)
	DeleteApplication(appID string) error
}

// ApplicationService is the default implementation of the ApplicationServiceInterface.
type ApplicationService struct {
	Store store.ApplicationStoreInterface
}

// GetApplicationService creates a new instance of ApplicationService.
func GetApplicationService() ApplicationServiceInterface {
	return &ApplicationService{
		Store: store.NewApplicationStore(),
	}
}

// GetOAuthApplication retrieves the OAuth application based on the client id.
func (as *ApplicationService) GetOAuthApplication(clientID string) (*model.OAuthAppConfigProcessed, error) {
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationService"))
	oauthApp, err := as.Store.GetOAuthApplication(clientID)
	if err != nil {
		logger.Error("Failed to retrieve OAuth application", log.Error(err), log.String("clientID", clientID))
		return nil, err
	}

	return oauthApp, nil
}

// CreateApplication creates the application.
func (as *ApplicationService) CreateApplication(app *model.ApplicationDTO) (*model.ApplicationDTO, error) {
	if app == nil {
		return nil, errors.New("application is nil")
	}
	if app.Name == "" {
		return nil, errors.New("application name cannot be empty")
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	if len(app.InboundAuthConfig) == 0 || app.InboundAuthConfig[0].Type != constants.OAuthInboundAuthType {
		return nil, errors.New("invalid inbound authentication configuration")
	}
	inboundAuthConfig := app.InboundAuthConfig[0]
	if inboundAuthConfig.OAuthAppConfig == nil {
		return nil, errors.New("OAuth application configuration is nil")
	}
	if inboundAuthConfig.OAuthAppConfig.ClientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if inboundAuthConfig.OAuthAppConfig.ClientSecret == "" {
		return nil, errors.New("client secret cannot be empty")
	}
	if len(inboundAuthConfig.OAuthAppConfig.RedirectURIs) == 0 {
		return nil, errors.New("at least one callback URL is required")
	}

	if err := validateAuthFlowGraphID(app); err != nil {
		return nil, err
	}
	if err := validateRegistrationFlowGraphID(app); err != nil {
		return nil, err
	}

	if app.URL != "" && !sysutils.IsValidURI(app.URL) {
		return nil, errors.New("application URL is not a valid URI")
	}
	if app.LogoURL != "" && !sysutils.IsValidURI(app.LogoURL) {
		return nil, errors.New("application logo URL is not a valid URI")
	}

	cert, err := getValidatedCertificate(app)
	if err != nil {
		return nil, err
	}

	appID := utils.GenerateUUID()
	processedInboundAuthConfig := model.InboundAuthConfigProcessed{
		Type: constants.OAuthInboundAuthType,
		OAuthAppConfig: &model.OAuthAppConfigProcessed{
			AppID:              appID,
			ClientID:           inboundAuthConfig.OAuthAppConfig.ClientID,
			HashedClientSecret: hash.HashString(inboundAuthConfig.OAuthAppConfig.ClientSecret),
			RedirectURIs:       inboundAuthConfig.OAuthAppConfig.RedirectURIs,
			GrantTypes:         inboundAuthConfig.OAuthAppConfig.GrantTypes,
		},
	}
	processedDTO := &model.ApplicationProcessedDTO{
		ID:                        appID,
		Name:                      app.Name,
		Description:               app.Description,
		AuthFlowGraphID:           app.AuthFlowGraphID,
		RegistrationFlowGraphID:   app.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: app.IsRegistrationFlowEnabled,
		URL:                       app.URL,
		LogoURL:                   app.LogoURL,
		Certificate:               cert,
		InboundAuthConfig:         []model.InboundAuthConfigProcessed{processedInboundAuthConfig},
	}

	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationService"))

	// Create the application.
	err = as.Store.CreateApplication(*processedDTO)
	if err != nil {
		logger.Error("Failed to create application", log.Error(err))
		return nil, err
	}

	returnApp := &model.ApplicationDTO{
		ID:                        appID,
		Name:                      app.Name,
		Description:               app.Description,
		AuthFlowGraphID:           app.AuthFlowGraphID,
		RegistrationFlowGraphID:   app.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: app.IsRegistrationFlowEnabled,
		URL:                       app.URL,
		LogoURL:                   app.LogoURL,
		Certificate:               cert,
		InboundAuthConfig:         []model.InboundAuthConfig{inboundAuthConfig},
	}
	return returnApp, nil
}

// GetApplicationList list the applications.
func (as *ApplicationService) GetApplicationList() ([]model.BasicApplicationDTO, error) {
	applications, err := as.Store.GetApplicationList()
	if err != nil {
		return nil, err
	}

	return applications, nil
}

// GetApplication get the application for given app id.
func (as *ApplicationService) GetApplication(appID string) (*model.ApplicationProcessedDTO, error) {
	if appID == "" {
		return nil, errors.New("application ID is empty")
	}

	application, err := as.Store.GetApplication(appID)
	if err != nil {
		return nil, err
	}

	return &application, nil
}

// UpdateApplication update the application for given app id.
func (as *ApplicationService) UpdateApplication(appID string, app *model.ApplicationDTO) (
	*model.ApplicationDTO, error) {
	if appID == "" {
		return nil, errors.New("application ID is empty")
	}
	if app == nil {
		return nil, errors.New("application is nil")
	}
	if app.Name == "" {
		return nil, errors.New("application name cannot be empty")
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	if len(app.InboundAuthConfig) == 0 || app.InboundAuthConfig[0].Type != constants.OAuthInboundAuthType {
		return nil, errors.New("invalid inbound authentication configuration")
	}
	inboundAuthConfig := app.InboundAuthConfig[0]
	if inboundAuthConfig.OAuthAppConfig == nil {
		return nil, errors.New("OAuth application configuration is nil")
	}
	if inboundAuthConfig.OAuthAppConfig.ClientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if inboundAuthConfig.OAuthAppConfig.ClientSecret == "" {
		return nil, errors.New("client secret cannot be empty")
	}
	if len(inboundAuthConfig.OAuthAppConfig.RedirectURIs) == 0 {
		return nil, errors.New("at least one callback URL is required")
	}

	if err := validateAuthFlowGraphID(app); err != nil {
		return nil, err
	}
	if err := validateRegistrationFlowGraphID(app); err != nil {
		return nil, err
	}

	if app.URL != "" && !sysutils.IsValidURI(app.URL) {
		return nil, errors.New("application URL is not a valid URI")
	}
	if app.LogoURL != "" && !sysutils.IsValidURI(app.LogoURL) {
		return nil, errors.New("application logo URL is not a valid URI")
	}

	cert, err := getValidatedCertificate(app)
	if err != nil {
		return nil, err
	}

	processedInboundAuthConfig := model.InboundAuthConfigProcessed{
		Type: constants.OAuthInboundAuthType,
		OAuthAppConfig: &model.OAuthAppConfigProcessed{
			AppID:              appID,
			ClientID:           inboundAuthConfig.OAuthAppConfig.ClientID,
			HashedClientSecret: hash.HashString(inboundAuthConfig.OAuthAppConfig.ClientSecret),
			RedirectURIs:       inboundAuthConfig.OAuthAppConfig.RedirectURIs,
			GrantTypes:         inboundAuthConfig.OAuthAppConfig.GrantTypes,
		},
	}
	processedDTO := &model.ApplicationProcessedDTO{
		ID:                        appID,
		Name:                      app.Name,
		Description:               app.Description,
		AuthFlowGraphID:           app.AuthFlowGraphID,
		RegistrationFlowGraphID:   app.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: app.IsRegistrationFlowEnabled,
		URL:                       app.URL,
		LogoURL:                   app.LogoURL,
		Certificate:               cert,
		InboundAuthConfig:         []model.InboundAuthConfigProcessed{processedInboundAuthConfig},
	}

	err = as.Store.UpdateApplication(processedDTO)
	if err != nil {
		return nil, err
	}

	returnApp := &model.ApplicationDTO{
		ID:                        appID,
		Name:                      app.Name,
		Description:               app.Description,
		AuthFlowGraphID:           app.AuthFlowGraphID,
		RegistrationFlowGraphID:   app.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: app.IsRegistrationFlowEnabled,
		URL:                       app.URL,
		LogoURL:                   app.LogoURL,
		Certificate:               cert,
		InboundAuthConfig:         []model.InboundAuthConfig{inboundAuthConfig},
	}
	return returnApp, nil
}

// DeleteApplication delete the application for given app id.
func (as *ApplicationService) DeleteApplication(appID string) error {
	if appID == "" {
		return errors.New("application ID is empty")
	}

	err := as.Store.DeleteApplication(appID)
	if err != nil {
		return err
	}

	return nil
}

// validateAuthFlowGraphID validates the auth flow graph ID for the application.
// If the graph ID is not provided, it sets the default authentication flow graph ID.
func validateAuthFlowGraphID(app *model.ApplicationDTO) error {
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
func validateRegistrationFlowGraphID(app *model.ApplicationDTO) error {
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

// getValidatedCertificate validates and returns the certificate for the application.
func getValidatedCertificate(app *model.ApplicationDTO) (*model.Certificate, error) {
	if app.Certificate == nil {
		return &model.Certificate{
			Type:  constants.CertificateTypeNone,
			Value: "",
		}, nil
	}
	if app.Certificate.Type == "" {
		return &model.Certificate{
			Type:  constants.CertificateTypeNone,
			Value: "",
		}, nil
	}
	switch app.Certificate.Type {
	case constants.CertificateTypeNone:
		return &model.Certificate{
			Type:  constants.CertificateTypeNone,
			Value: "",
		}, nil
	case constants.CertificateTypeJWKS:
		if app.Certificate.Value == "" {
			return nil, errors.New("JWKS certificate value cannot be empty")
		}
		return &model.Certificate{
			ID:    sysutils.GenerateUUID(),
			Type:  constants.CertificateTypeJWKS,
			Value: app.Certificate.Value,
		}, nil
	case constants.CertificateTypeJWKSURI:
		if !sysutils.IsValidURI(app.Certificate.Value) {
			return nil, errors.New("JWKS URI certificate value is not a valid URI")
		}
		return &model.Certificate{
			ID:    sysutils.GenerateUUID(),
			Type:  constants.CertificateTypeJWKSURI,
			Value: app.Certificate.Value,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", app.Certificate.Type)
	}
}
