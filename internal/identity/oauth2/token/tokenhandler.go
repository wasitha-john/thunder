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

package token

import (
	"encoding/json"
	"net/http"

	appprovider "github.com/asgardeo/thunder/internal/application/provider"
	apputils "github.com/asgardeo/thunder/internal/application/utils"
	"github.com/asgardeo/thunder/internal/identity/oauth2/constants"
	"github.com/asgardeo/thunder/internal/identity/oauth2/granthandlers"
	"github.com/asgardeo/thunder/internal/identity/oauth2/model"
	scopeprovider "github.com/asgardeo/thunder/internal/identity/scope/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/utils"
)

type TokenHandler struct{}

// HandleTokenRequest handles the token request for OAuth 2.0.
// It validates the client credentials and delegates to the appropriate grant handler.
func (th *TokenHandler) HandleTokenRequest(respWriter http.ResponseWriter, request *http.Request) {

	logger := log.GetLogger().With(log.String(log.LOGGER_KEY_COMPONENT_NAME, "TokenHandler"))

	// Parse the form data from the request body.
	if err := request.ParseForm(); err != nil {
		utils.WriteJSONError(respWriter, constants.ERROR_INVALID_REQUEST, "Failed to parse request body", http.StatusBadRequest, nil)
		return
	}

	// Validate the grant_type.
	grantType := request.FormValue(constants.GRANT_TYPE)
	if grantType == "" {
		utils.WriteJSONError(respWriter, constants.ERROR_INVALID_REQUEST, "Missing grant_type parameter", http.StatusBadRequest, nil)
	}

	var grantHandler granthandlers.GrantHandler
	switch grantType {
	case constants.GRANT_TYPE_CLIENT_CREDENTIALS:
		grantHandler = &granthandlers.ClientCredentialsGrantHandler{}
	default:
		utils.WriteJSONError(respWriter, constants.ERROR_UNSUPPORTED_GRANT_TYPE, "Unsupported grant type", http.StatusBadRequest, nil)
		return
	}

	// Extract client credentials from the request.
	clientId := ""
	clientSecret := ""
	if request.Header.Get("Authorization") != "" {
		var err error
		clientId, clientSecret, err = utils.ExtractBasicAuthCredentials(request)
		if err != nil {
			if err.Error() == "invalid authorization header" {
				responseHeaders := []map[string]string{
					{"WWW-Authenticate": "Basic"},
				}
				utils.WriteJSONError(respWriter, constants.ERROR_INVALID_CLIENT, "Invalid client credentials", http.StatusUnauthorized, responseHeaders)
				return
			}
			utils.WriteJSONError(respWriter, constants.ERROR_INVALID_CLIENT, "Invalid client credentials", http.StatusUnauthorized, nil)
			return
		}
	}

	// Check for client credentials in the request body.
	clientIdFromBody := request.FormValue(constants.CLIENT_ID)
	clientSecretFromBody := request.FormValue(constants.CLIENT_SECRET)
	if clientIdFromBody != "" && clientSecretFromBody != "" {
		if clientId != "" && clientSecret != "" {
			utils.WriteJSONError(respWriter, constants.ERROR_INVALID_REQUEST, "Authorization information is provided in both header and body", http.StatusBadRequest, nil)
			return
		}

		clientId = clientIdFromBody
		clientSecret = clientSecretFromBody
	}

	// Construct the token request.
	tokenRequest := &model.TokenRequest{
		GrantType:    grantType,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        request.FormValue("scope"),
		Username:     request.FormValue("username"),
		Password:     request.FormValue("password"),
		RefreshToken: request.FormValue("refresh_token"),
		CodeVerifier: request.FormValue("code_verifier"),
		Code:         request.FormValue("code"),
		RedirectUri:  request.FormValue("redirect_uri"),
	}

	// Validate the token request.
	tokenError := grantHandler.ValidateGrant(tokenRequest)
	if tokenError != nil && tokenError.Error != "" {
		utils.WriteJSONError(respWriter, tokenError.Error, tokenError.ErrorDescription, http.StatusBadRequest, nil)
		return
	}

	// Retrieve the OAuth application based on the client Id.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()

	oauthApp, err := appService.GetOAuthApplication(clientId)
	if err != nil || oauthApp == nil {
		utils.WriteJSONError(respWriter, constants.ERROR_INVALID_CLIENT, "Invalid client credentials", http.StatusUnauthorized, nil)
		return
	}

	// Validate grant type against the application.
	if !apputils.IsAllowedGrantType(oauthApp, tokenRequest.GrantType) {
		utils.WriteJSONError(respWriter, constants.ERROR_UNAUTHORIZED_CLIENT, "The authenticated client is not authorized to use this grant type", http.StatusUnauthorized, nil)
		return
	}

	// Validate and filter scopes.
	scopeValidatorProvider := scopeprovider.NewScopeValidatorProvider()
	scopeValidator := scopeValidatorProvider.GetScopeValidator()

	validScopes, scopeError := scopeValidator.ValidateScopes(tokenRequest.Scope, oauthApp.ClientId)
	if scopeError != nil {
		utils.WriteJSONError(respWriter, scopeError.Error, scopeError.ErrorDescription, http.StatusBadRequest, nil)
		return
	}
	tokenRequest.Scope = validScopes

	// Delegate to the grant handler.
	tokenResponse, tokenError := grantHandler.HandleGrant(tokenRequest, oauthApp)
	if tokenError != nil && tokenError.Error != "" {
		utils.WriteJSONError(respWriter, tokenError.Error, tokenError.ErrorDescription, http.StatusBadRequest, nil)
		return
	}

	// Log successful token generation.
	logger.Info("Token generated successfully", log.String("client_id", clientId))

	// Set the response headers.
	respWriter.Header().Set("Content-Type", "application/json")
	respWriter.Header().Set("Cache-Control", "no-store")
	respWriter.Header().Set("Pragma", "no-cache")

	// Write the token response.
	respWriter.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(respWriter).Encode(tokenResponse); err != nil {
		logger.Error("Failed to write token response", log.Error(err))
		http.Error(respWriter, "Failed to write token response", http.StatusInternalServerError)
		return
	}
	// Log the token response.
	logger.Info("Token response sent", log.String("client_id", clientId))
}
