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

// Package handler provides HTTP handlers for managing application-related API requests.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/asgardeo/thunder/internal/application/constants"
	"github.com/asgardeo/thunder/internal/application/model"
	appprovider "github.com/asgardeo/thunder/internal/application/provider"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// ApplicationHandler defines the handler for managing application API requests.
type ApplicationHandler struct {
	ApplicationProvider appprovider.ApplicationProviderInterface
}

// NewApplicationHandler creates a new instance of ApplicationHandler.
func NewApplicationHandler() *ApplicationHandler {
	return &ApplicationHandler{
		ApplicationProvider: appprovider.NewApplicationProvider(),
	}
}

// HandleApplicationPostRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationPostRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationHandler"))

	appRequest, err := sysutils.DecodeJSONBody[model.ApplicationRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: constants.ErrorInvalidRequestFormat.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	inboundAuthConfig := model.InboundAuthConfig{
		Type: constants.OAuthInboundAuthType,
		OAuthAppConfig: &model.OAuthAppConfig{
			ClientID:                appRequest.ClientID,
			ClientSecret:            appRequest.ClientSecret,
			RedirectURIs:            appRequest.RedirectURIs,
			GrantTypes:              appRequest.GrantTypes,
			ResponseTypes:           appRequest.ResponseTypes,
			TokenEndpointAuthMethod: appRequest.TokenEndpointAuthMethod,
		},
	}
	appDTO := model.ApplicationDTO{
		Name:                      appRequest.Name,
		Description:               appRequest.Description,
		AuthFlowGraphID:           appRequest.AuthFlowGraphID,
		RegistrationFlowGraphID:   appRequest.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: appRequest.IsRegistrationFlowEnabled,
		URL:                       appRequest.URL,
		LogoURL:                   appRequest.LogoURL,
		Certificate:               appRequest.Certificate,
		InboundAuthConfig:         []model.InboundAuthConfig{inboundAuthConfig},
	}

	// Create the app using the application service.
	appService := ah.ApplicationProvider.GetApplicationService()
	createdAppDTO, svcErr := appService.CreateApplication(&appDTO)
	if svcErr != nil {
		ah.handleError(w, logger, svcErr)
		return
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	if len(createdAppDTO.InboundAuthConfig) == 0 ||
		createdAppDTO.InboundAuthConfig[0].Type != constants.OAuthInboundAuthType {
		logger.Error("Unsupported inbound authentication type returned",
			log.String("type", string(createdAppDTO.InboundAuthConfig[0].Type)))

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	returnInboundAuthConfig := createdAppDTO.InboundAuthConfig[0]
	if returnInboundAuthConfig.OAuthAppConfig == nil {
		logger.Error("OAuth application configuration is nil")

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	redirectURIs := returnInboundAuthConfig.OAuthAppConfig.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = []string{}
	}
	grantTypes := returnInboundAuthConfig.OAuthAppConfig.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []oauth2const.GrantType{}
	}
	responseTypes := returnInboundAuthConfig.OAuthAppConfig.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []oauth2const.ResponseType{}
	}
	tokenAuthMethods := returnInboundAuthConfig.OAuthAppConfig.TokenEndpointAuthMethod
	if len(tokenAuthMethods) == 0 {
		tokenAuthMethods = []oauth2const.TokenEndpointAuthMethod{}
	}

	returnApp := model.ApplicationCompleteResponse{
		ID:                        createdAppDTO.ID,
		Name:                      createdAppDTO.Name,
		Description:               createdAppDTO.Description,
		ClientID:                  returnInboundAuthConfig.OAuthAppConfig.ClientID,
		ClientSecret:              returnInboundAuthConfig.OAuthAppConfig.ClientSecret,
		RedirectURIs:              redirectURIs,
		GrantTypes:                grantTypes,
		ResponseTypes:             responseTypes,
		TokenEndpointAuthMethod:   tokenAuthMethods,
		AuthFlowGraphID:           createdAppDTO.AuthFlowGraphID,
		RegistrationFlowGraphID:   createdAppDTO.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: createdAppDTO.IsRegistrationFlowEnabled,
		URL:                       createdAppDTO.URL,
		LogoURL:                   createdAppDTO.LogoURL,
		Certificate:               createdAppDTO.Certificate,
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusCreated)

	if encodeErr := json.NewEncoder(w).Encode(returnApp); encodeErr != nil {
		logger.Error("Error encoding response", log.Error(encodeErr))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleApplicationListRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationHandler"))

	appService := ah.ApplicationProvider.GetApplicationService()
	listResponse, svcErr := appService.GetApplicationList()
	if svcErr != nil {
		ah.handleError(w, logger, svcErr)
		return
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if encodeErr := json.NewEncoder(w).Encode(listResponse); encodeErr != nil {
		logger.Error("Error encoding response", log.Error(encodeErr))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleApplicationGetRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationHandler"))

	id := r.PathValue("id")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidApplicationID.Code,
			Message:     constants.ErrorInvalidApplicationID.Error,
			Description: constants.ErrorInvalidApplicationID.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	appService := ah.ApplicationProvider.GetApplicationService()
	appDTO, svcErr := appService.GetApplication(id)
	if svcErr != nil {
		ah.handleError(w, logger, svcErr)
		return
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	if len(appDTO.InboundAuthConfig) == 0 || appDTO.InboundAuthConfig[0].Type != constants.OAuthInboundAuthType {
		logger.Error("Unsupported inbound authentication type returned",
			log.String("type", string(appDTO.InboundAuthConfig[0].Type)))

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	returnInboundAuthConfig := appDTO.InboundAuthConfig[0]
	if returnInboundAuthConfig.OAuthAppConfig == nil {
		logger.Error("OAuth application configuration is nil")

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	redirectURIs := returnInboundAuthConfig.OAuthAppConfig.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = []string{}
	}
	grantTypes := returnInboundAuthConfig.OAuthAppConfig.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []oauth2const.GrantType{}
	}
	responseTypes := returnInboundAuthConfig.OAuthAppConfig.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []oauth2const.ResponseType{}
	}
	tokenAuthMethods := returnInboundAuthConfig.OAuthAppConfig.TokenEndpointAuthMethod
	if len(tokenAuthMethods) == 0 {
		tokenAuthMethods = []oauth2const.TokenEndpointAuthMethod{}
	}

	returnApp := model.ApplicationGetResponse{
		ID:                        appDTO.ID,
		Name:                      appDTO.Name,
		Description:               appDTO.Description,
		ClientID:                  returnInboundAuthConfig.OAuthAppConfig.ClientID,
		RedirectURIs:              redirectURIs,
		GrantTypes:                grantTypes,
		ResponseTypes:             responseTypes,
		TokenEndpointAuthMethod:   tokenAuthMethods,
		AuthFlowGraphID:           appDTO.AuthFlowGraphID,
		RegistrationFlowGraphID:   appDTO.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: appDTO.IsRegistrationFlowEnabled,
		URL:                       appDTO.URL,
		LogoURL:                   appDTO.LogoURL,
		Certificate:               appDTO.Certificate,
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if encodeErr := json.NewEncoder(w).Encode(returnApp); encodeErr != nil {
		logger.Error("Error encoding response", log.Error(encodeErr))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleApplicationPutRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationPutRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationHandler"))

	id := r.PathValue("id")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidApplicationID.Code,
			Message:     constants.ErrorInvalidApplicationID.Error,
			Description: constants.ErrorInvalidApplicationID.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	appRequest, err := sysutils.DecodeJSONBody[model.ApplicationRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: constants.ErrorInvalidRequestFormat.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	inboundAuthConfig := model.InboundAuthConfig{
		Type: constants.OAuthInboundAuthType,
		OAuthAppConfig: &model.OAuthAppConfig{
			ClientID:                appRequest.ClientID,
			ClientSecret:            appRequest.ClientSecret,
			RedirectURIs:            appRequest.RedirectURIs,
			GrantTypes:              appRequest.GrantTypes,
			ResponseTypes:           appRequest.ResponseTypes,
			TokenEndpointAuthMethod: appRequest.TokenEndpointAuthMethod,
		},
	}
	updateReqAppDTO := model.ApplicationDTO{
		ID:                        id,
		Name:                      appRequest.Name,
		Description:               appRequest.Description,
		AuthFlowGraphID:           appRequest.AuthFlowGraphID,
		RegistrationFlowGraphID:   appRequest.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: appRequest.IsRegistrationFlowEnabled,
		URL:                       appRequest.URL,
		LogoURL:                   appRequest.LogoURL,
		Certificate:               appRequest.Certificate,
		InboundAuthConfig:         []model.InboundAuthConfig{inboundAuthConfig},
	}

	// Update the application using the application service.
	appService := ah.ApplicationProvider.GetApplicationService()
	updatedAppDTO, svcErr := appService.UpdateApplication(id, &updateReqAppDTO)
	if svcErr != nil {
		ah.handleError(w, logger, svcErr)
		return
	}

	// TODO: Need to refactor when supporting other/multiple inbound auth types.
	if len(updatedAppDTO.InboundAuthConfig) == 0 ||
		updatedAppDTO.InboundAuthConfig[0].Type != constants.OAuthInboundAuthType {
		logger.Error("Unsupported inbound authentication type returned",
			log.String("type", string(updatedAppDTO.InboundAuthConfig[0].Type)))

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	returnInboundAuthConfig := updatedAppDTO.InboundAuthConfig[0]
	if returnInboundAuthConfig.OAuthAppConfig == nil {
		logger.Error("OAuth application configuration is nil")

		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInternalServerError.Code,
			Message:     constants.ErrorInternalServerError.Error,
			Description: constants.ErrorInternalServerError.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	redirectURIs := returnInboundAuthConfig.OAuthAppConfig.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = []string{}
	}
	grantTypes := returnInboundAuthConfig.OAuthAppConfig.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []oauth2const.GrantType{}
	}
	responseTypes := returnInboundAuthConfig.OAuthAppConfig.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []oauth2const.ResponseType{}
	}
	tokenAuthMethods := returnInboundAuthConfig.OAuthAppConfig.TokenEndpointAuthMethod
	if len(tokenAuthMethods) == 0 {
		tokenAuthMethods = []oauth2const.TokenEndpointAuthMethod{}
	}

	returnApp := model.ApplicationCompleteResponse{
		ID:                        updatedAppDTO.ID,
		Name:                      updatedAppDTO.Name,
		Description:               updatedAppDTO.Description,
		ClientID:                  returnInboundAuthConfig.OAuthAppConfig.ClientID,
		ClientSecret:              returnInboundAuthConfig.OAuthAppConfig.ClientSecret,
		RedirectURIs:              redirectURIs,
		GrantTypes:                grantTypes,
		ResponseTypes:             responseTypes,
		TokenEndpointAuthMethod:   tokenAuthMethods,
		AuthFlowGraphID:           updatedAppDTO.AuthFlowGraphID,
		RegistrationFlowGraphID:   updatedAppDTO.RegistrationFlowGraphID,
		IsRegistrationFlowEnabled: updatedAppDTO.IsRegistrationFlowEnabled,
		URL:                       updatedAppDTO.URL,
		LogoURL:                   updatedAppDTO.LogoURL,
		Certificate:               updatedAppDTO.Certificate,
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if encodeErr := json.NewEncoder(w).Encode(returnApp); encodeErr != nil {
		logger.Error("Error encoding response", log.Error(encodeErr))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleApplicationDeleteRequest handles the application request.
func (ah *ApplicationHandler) HandleApplicationDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ApplicationHandler"))

	id := r.PathValue("id")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidApplicationID.Code,
			Message:     constants.ErrorInvalidApplicationID.Error,
			Description: constants.ErrorInvalidApplicationID.ErrorDescription,
		}
		if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
			logger.Error("Error encoding error response", log.Error(encodeErr))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	appService := ah.ApplicationProvider.GetApplicationService()
	svcErr := appService.DeleteApplication(id)
	if svcErr != nil {
		ah.handleError(w, logger, svcErr)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleError handles service errors and returns appropriate HTTP responses.
func (ah *ApplicationHandler) handleError(w http.ResponseWriter, logger *log.Logger,
	svcErr *serviceerror.ServiceError) {
	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)

	errResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}

	statusCode := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		if svcErr.Code == constants.ErrorApplicationNotFound.Code {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusBadRequest
		}
	}
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error("Error encoding error response", log.Error(err))
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}
