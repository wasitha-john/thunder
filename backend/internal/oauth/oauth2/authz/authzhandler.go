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

// Package authz provides handlers and utilities for managing OAuth2 authorization requests.
package authz

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	appprovider "github.com/asgardeo/thunder/internal/application/provider"
	authzmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	authzutils "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/utils"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/model"
	oauthutils "github.com/asgardeo/thunder/internal/oauth/oauth2/utils"
	sessionmodel "github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	sessionutils "github.com/asgardeo/thunder/internal/oauth/session/utils"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// AuthorizeHandlerInterface defines the interface for handling OAuth2 authorization requests.
type AuthorizeHandlerInterface interface {
	HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request)
}

// AuthorizeHandler implements the AuthorizeHandlerInterface for handling OAuth2 authorization requests.
type AuthorizeHandler struct {
	authValidator AuthorizationValidatorInterface
}

// NewAuthorizeHandler creates a new instance of AuthorizeHandler.
func NewAuthorizeHandler() AuthorizeHandlerInterface {
	return &AuthorizeHandler{
		authValidator: NewAuthorizationValidator(),
	}
}

// HandleAuthorizeRequest handles the OAuth2 authorization request.
func (ah *AuthorizeHandler) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger()

	// Construct the OAuthMessage.
	oAuthMessage, err := oauthutils.GetOAuthMessage(r, w)
	if err != nil {
		logger.Error("Failed to construct OAuthMessage", log.Error(err))
		utils.WriteJSONError(w, constants.ErrorInvalidRequest,
			"Invalid authorization request", http.StatusBadRequest, nil)
		return
	}
	if oAuthMessage == nil {
		logger.Error("OAuthMessage is nil")
		utils.WriteJSONError(w, constants.ErrorInvalidRequest,
			"Invalid authorization request", http.StatusBadRequest, nil)
		return
	}

	switch oAuthMessage.RequestType {
	case constants.TypeInitialAuthorizationRequest:
		ah.handleInitialAuthorizationRequest(oAuthMessage, w, r)
	case constants.TypeAuthorizationResponseFromEngine:
		ah.handleAuthenticationResponse(oAuthMessage, w, r)
	case constants.TypeConsentResponseFromUser:
	// TODO: Handle the consent response from the user.
	//  Verify whether we need separate session data key for consent flow.
	//  Alternatively could add consent info also to the same session object.
	default:
		// Handle the case where the request is not recognized.
		utils.WriteJSONError(w, constants.ErrorInvalidRequest,
			"Invalid authorization request", http.StatusBadRequest, nil)
	}
}

// handleInitialAuthorizationRequest handles the initial authorization request from the client.
func (ah *AuthorizeHandler) handleInitialAuthorizationRequest(msg *authzmodel.OAuthMessage,
	w http.ResponseWriter, r *http.Request) {
	// Extract required parameters.
	clientID := msg.RequestQueryParams[constants.ClientID]
	redirectURI := msg.RequestQueryParams[constants.RedirectURI]
	scope := msg.RequestQueryParams[constants.Scope]
	state := msg.RequestQueryParams[constants.State]
	responseType := msg.RequestQueryParams[constants.ResponseType]

	if clientID == "" {
		redirectToErrorPage(w, r, constants.ErrorInvalidRequest, "Missing client_id parameter")
		return
	}

	// Retrieve the OAuth application based on the client Id.
	appProvider := appprovider.NewApplicationProvider()
	appService := appProvider.GetApplicationService()

	app, err := appService.GetOAuthApplication(clientID)
	if err != nil || app == nil {
		redirectToErrorPage(w, r, constants.ErrorInvalidClient, "Invalid client_id")
		return
	}

	// Validate the authorization request.
	sendErrorToApp, errorCode, errorMessage := ah.authValidator.validateInitialAuthorizationRequest(msg, app)
	if errorCode != "" {
		if sendErrorToApp && redirectURI != "" {
			// Redirect to the redirect URI with an error.
			redirectURI, err := oauthutils.GetURIWithQueryParams(redirectURI, map[string]string{
				constants.Error:            errorCode,
				constants.ErrorDescription: errorMessage,
			})
			if err != nil {
				redirectToErrorPage(w, r, constants.ErrorServerError, "Failed to redirect to login page")
				return
			}

			if state != "" {
				redirectURI += "&" + constants.State + "=" + state
			}
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		} else {
			redirectToErrorPage(w, r, errorCode, errorMessage)
			return
		}
	}

	// Construct session data.
	oauthParams := model.OAuthParameters{
		SessionDataKey: sessionutils.GenerateNewSessionDataKey(),
		State:          state,
		AppID:          app.ID,
		ClientID:       clientID,
		RedirectURI:    redirectURI,
		ResponseType:   responseType,
		Scopes:         scope,
	}

	// Set the redirect URI if not provided in the request. Invalid cases are already handled at this point.
	// TODO: This should be removed when supporting other means of authorization.
	if redirectURI == "" {
		oauthParams.RedirectURI = app.RedirectURIs[0]
	}

	sessionData := sessionmodel.SessionData{
		OAuthParameters: oauthParams,
		AuthTime:        time.Now(),
	}

	// Store session data in the session store.
	sessionDataStore := sessionstore.GetSessionDataStore()
	sessionDataStore.AddSession(oauthParams.SessionDataKey, sessionData)

	// Add required query parameters.
	queryParams := make(map[string]string)
	queryParams[constants.SessionDataKey] = oauthParams.SessionDataKey

	// Add insecure warning if the redirect URI is not using TLS.
	// TODO: May require another redirection to a warn consent page when it directly goes to a federated IDP.
	parsedRedirectURI, err := utils.ParseURL(oauthParams.RedirectURI)
	if err != nil {
		redirectToErrorPage(w, r, constants.ErrorServerError, "Failed to redirect to login page")
		return
	}
	if parsedRedirectURI.Scheme == "http" {
		queryParams[constants.ShowInsecureWarning] = "true"
	}

	redirectToLoginPage(w, r, queryParams)
}

func (ah *AuthorizeHandler) handleAuthenticationResponse(msg *authzmodel.OAuthMessage,
	w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger()

	// Validate the session data.
	sessionData := msg.SessionData
	if sessionData == nil {
		redirectToErrorPage(w, r, constants.ErrorInvalidRequest, "Invalid authorization request")
		return
	}

	// If the user is not authenticated, redirect to the redirect URI with an error.
	authResult := sessionData.AuthenticatedUser
	if !authResult.IsAuthenticated {
		redirectURI := sessionData.OAuthParameters.RedirectURI
		if redirectURI == "" {
			logger.Error("Redirect URI is empty")
			redirectToErrorPage(w, r, constants.ErrorInvalidRequest, "Invalid redirect URI")
			return
		}

		queryParams := map[string]string{
			constants.Error:            constants.ErrorAccessDenied,
			constants.ErrorDescription: "User authentication failed",
		}
		if sessionData.OAuthParameters.State != "" {
			queryParams[constants.State] = sessionData.OAuthParameters.State
		}

		var err error
		redirectURI, err = oauthutils.GetURIWithQueryParams(redirectURI, queryParams)
		if err != nil {
			logger.Error("Failed to construct redirect URI", log.Error(err))
			redirectToErrorPage(w, r, constants.ErrorServerError, "Failed to redirect to login page")
			return
		}

		http.Redirect(w, r, redirectURI, http.StatusFound)
	}

	// TODO: Do user authorization.
	//  Should validate for the scopes as well.

	// Generate the authorization code.
	authzCode, err := authzutils.GetAuthorizationCode(msg)
	if err != nil {
		logger.Error("Failed to generate authorization code", log.Error(err))
		redirectToErrorPage(w, r, constants.ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Persist the authorization code.
	persistErr := InsertAuthorizationCode(authzCode)
	if persistErr != nil {
		logger.Error("Failed to persist authorization code", log.Error(persistErr))
		redirectToErrorPage(w, r, constants.ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Redirect to the redirect URI with the authorization code.
	redirectURI := authzCode.RedirectURI + "?code=" + authzCode.Code
	if sessionData.OAuthParameters.State != "" {
		redirectURI += "&state=" + sessionData.OAuthParameters.State
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// redirectToErrorPage constructs the error page URL and redirects the user to it.
func redirectToErrorPage(w http.ResponseWriter, r *http.Request, code, msg string) {
	if w == nil || r == nil {
		log.GetLogger().Error("Response writer or request is nil. Cannot redirect to error page.")
		return
	}

	queryParams := map[string]string{
		"errorCode":    code,
		"errorMessage": msg,
	}
	redirectURL, err := getErrorPageURL(queryParams)
	if err != nil {
		log.GetLogger().Error("Failed to construct error page URL: " + err.Error())
		return
	}
	log.GetLogger().Info("Redirecting to error page: " + redirectURL)

	// Redirect with the request object.
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// getErrorPageURL constructs the error page URL with the provided query parameters.
func getErrorPageURL(queryParams map[string]string) (string, error) {
	gateClientConfig := config.GetThunderRuntime().Config.GateClient
	errorPageURL := (&url.URL{
		Scheme: gateClientConfig.Scheme,
		Host:   fmt.Sprintf("%s:%d", gateClientConfig.Hostname, gateClientConfig.Port),
		Path:   gateClientConfig.ErrorPath,
	}).String()

	return utils.GetURIWithQueryParams(errorPageURL, queryParams)
}

// redirectToLoginPage constructs the login page URL and redirects the user to it.
func redirectToLoginPage(w http.ResponseWriter, r *http.Request, queryParams map[string]string) {
	if w == nil || r == nil {
		log.GetLogger().Error("Response writer or request is nil. Cannot redirect to login page.")
		return
	}

	redirectURI, err := getLoginPageRedirectURI(queryParams)
	if err != nil {
		log.GetLogger().Error("Failed to construct login page URL: " + err.Error())
		return
	}
	log.GetLogger().Info("Redirecting to login page: " + redirectURI)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// getLoginPageRedirectURI constructs the login page URL with the provided query parameters.
func getLoginPageRedirectURI(queryParams map[string]string) (string, error) {
	gateClientConfig := config.GetThunderRuntime().Config.GateClient
	loginPageURL := (&url.URL{
		Scheme: gateClientConfig.Scheme,
		Host:   fmt.Sprintf("%s:%d", gateClientConfig.Hostname, gateClientConfig.Port),
		Path:   gateClientConfig.LoginPath,
	}).String()

	return utils.GetURIWithQueryParams(loginPageURL, queryParams)
}
