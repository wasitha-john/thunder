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

package authz

import (
	"github.com/asgardeo/thunder/internal/system/utils"
	"net/http"
	"time"

	appprovider "github.com/asgardeo/thunder/internal/application/provider"
	authzmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	authzutils "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/utils"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/model"
	oauthutils "github.com/asgardeo/thunder/internal/oauth/oauth2/utils"
	sessionmodel "github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	"github.com/asgardeo/thunder/internal/system/log"
)

type AuthorizeHandler struct {
	authValidator *AuthorizationValidator
}

// HandleAuthorizeRequest handles the OAuth2 authorization request.
func (ah *AuthorizeHandler) HandleAuthorizeRequest(responseWriter http.ResponseWriter, request *http.Request) {

	logger := log.GetLogger()

	// Construct the OAuthMessage.
	oAuthMessage, err := oauthutils.GetOAuthMessage(request, responseWriter)
	if err != nil {
		logger.Error("Failed to construct OAuthMessage", log.Error(err))
		utils.WriteJSONError(responseWriter, constants.ERROR_INVALID_REQUEST,
			"Invalid authorization request", http.StatusBadRequest, nil)
		return
	}
	if oAuthMessage == nil {
		logger.Error("OAuthMessage is nil")
		utils.WriteJSONError(responseWriter, constants.ERROR_INVALID_REQUEST,
			"Invalid authorization request", http.StatusBadRequest, nil)
		return
	}

	switch oAuthMessage.RequestType {
	case constants.TYPE_INITIAL_AUTHORIZATION_REQUEST:
		ah.handleInitialAuthorizationRequest(oAuthMessage, responseWriter, request)
	case constants.TYPE_AUTHORIZATION_RESPONSE_FROM_FRAMEWORK:
		ah.handleAuthenticationResponse(oAuthMessage, responseWriter, request)
	case constants.TYPE_CONSENT_RESPONSE_FROM_USER:
	// TODO: Handle the consent response from the user.
	default:
		// Handle the case where the request is not recognized.
		utils.WriteJSONError(responseWriter, constants.ERROR_INVALID_REQUEST,
			"Invalid authorization request", http.StatusBadRequest, nil)
	}
}

// handleInitialAuthorizationRequest handles the initial authorization request from the client.
func (ah *AuthorizeHandler) handleInitialAuthorizationRequest(oAuthMessage *authzmodel.OAuthMessage,
	responseWriter http.ResponseWriter, request *http.Request) {

	// Validate the authorization request.
	errorCode, errorMessage := ah.authValidator.ValidateInitialAuthorizationRequest(oAuthMessage)
	if errorCode != "" {
		oauthutils.RedirectToErrorPage(responseWriter, request, errorCode, errorMessage)
		return
	}

	// Extract required parameters.
	clientId := oAuthMessage.RequestQueryParams[constants.CLIENT_ID]
	redirectUri := oAuthMessage.RequestQueryParams[constants.REDIRECT_URI]
	scope := oAuthMessage.RequestQueryParams[constants.SCOPE]
	state := oAuthMessage.RequestQueryParams[constants.STATE]
	responseType := oAuthMessage.RequestQueryParams[constants.RESPONSE_TYPE]

	// Retrieve the OAuth application based on the client Id.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()

	oauthApp, err := appService.GetOAuthApplication(clientId)
	if err != nil || oauthApp == nil {
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_INVALID_CLIENT, "Invalid client_id")
		return
	}

	// Validate the redirect URI against the registered application.
	if !oauthApp.IsValidRedirectURI(redirectUri) {
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_INVALID_REQUEST,
			"Your application's redirect URL does not match with the registered redirect URLs.")
		return
	}

	// Get query params sent in the request.
	queryParams := oAuthMessage.RequestQueryParams

	// Construct session data.
	oauthParams := model.OAuthParameters{
		SessionDataKey: oauthutils.GenerateNewSessionDataKey(),
		State:          state,
		ClientId:       clientId,
		RedirectUri:    redirectUri,
		ResponseType:   responseType,
		Scopes:         scope,
	}
	sessionData := sessionmodel.SessionData{
		OAuthParameters: oauthParams,
		AuthTime:        time.Now(),
	}

	// Store session data in the session store.
	sessionDataStore := sessionstore.GetSessionDataStore()
	sessionDataStore.AddSession(oauthParams.SessionDataKey, sessionData)

	// Add other required query parameters.
	queryParams[constants.SESSION_DATA_KEY] = oauthParams.SessionDataKey

	// Append required query parameters to the redirect URI.
	loginPageUri, err := oauthutils.GetLoginPageRedirectUri(queryParams)
	if err != nil {
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_SERVER_ERROR,
			"Failed to redirect to login page")
	} else {
		// Redirect user-agent to the login page.
		http.Redirect(responseWriter, request, loginPageUri, http.StatusFound)
	}
}

func (ah *AuthorizeHandler) handleAuthenticationResponse(oAuthMessage *authzmodel.OAuthMessage,
	responseWriter http.ResponseWriter, request *http.Request) {

	logger := log.GetLogger()

	// Validate the session data.
	sessionData := oAuthMessage.SessionData
	if sessionData == nil {
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_INVALID_REQUEST,
			"Invalid authorization request")
		return
	}

	// If the user is not authenticated, redirect to the redirect URI with an error.
	authResult := sessionData.LoggedInUser
	if !authResult.IsAuthenticated {
		redirectUri := sessionData.OAuthParameters.RedirectUri
		queryParams := map[string]string{
			constants.ERROR:             constants.ERROR_ACCESS_DENIED,
			constants.ERROR_DESCRIPTION: "User authentication failed",
		}
		if sessionData.OAuthParameters.State != "" {
			queryParams[constants.STATE] = sessionData.OAuthParameters.State
		}

		redirectUri, err := oauthutils.GetUriWithQueryParams(redirectUri, queryParams)
		if err != nil {
			logger.Error("Failed to construct redirect URI", log.Error(err))
			oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_SERVER_ERROR,
				"Failed to redirect to login page")
			return
		}

		http.Redirect(responseWriter, request, redirectUri, http.StatusFound)
	}

	// TODO: Do user authorization.
	//  Should validate for the scopes as well.

	// Generate the authorization code.
	authzCode, err := authzutils.GetAuthorizationCode(oAuthMessage)
	if err != nil {
		logger.Error("Failed to generate authorization code", log.Error(err))
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_SERVER_ERROR,
			"Failed to generate authorization code")
		return
	}

	// Persist the authorization code.
	persistErr := InsertAuthorizationCode(authzCode)
	if persistErr != nil {
		logger.Error("Failed to persist authorization code", log.Error(persistErr))
		oauthutils.RedirectToErrorPage(responseWriter, request, constants.ERROR_SERVER_ERROR,
			"Failed to generate authorization code")
		return
	}

	// Redirect to the redirect URI with the authorization code.
	redirectUri := authzCode.RedirectUri + "?code=" + authzCode.Code
	if sessionData.OAuthParameters.State != "" {
		redirectUri += "&state=" + sessionData.OAuthParameters.State
	}
	http.Redirect(responseWriter, request, redirectUri, http.StatusFound)
}
