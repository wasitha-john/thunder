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

// Package authn provides the implementation of the authentication handler and related functionalities.
package authn

import (
	"net/http"
	"strings"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/authn/utils"
	oauthconstants "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	oauthmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/model"
	sessionmodel "github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	sessionutils "github.com/asgardeo/thunder/internal/oauth/session/utils"
	"github.com/asgardeo/thunder/internal/outboundauth"
	"github.com/asgardeo/thunder/internal/outboundauth/basicauth"
	"github.com/asgardeo/thunder/internal/outboundauth/github"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

// AuthenticationHandler handles authentication requests.
type AuthenticationHandler struct {
}

// NewAuthenticationHandler creates a new instance of AuthenticationHandler.
func NewAuthenticationHandler() *AuthenticationHandler {
	return &AuthenticationHandler{}
}

// InitAuthenticationFlow initializes the authentication process.
func (ah *AuthenticationHandler) InitAuthenticationFlow(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthenticationHandler"))
	logger.Info("Initializing authentication flow.")

	// Handle the authentication request with the selected authenticator.
	selectedAuthenticator := r.URL.Query().Get("authenticator")
	authr := getAuthenticator(selectedAuthenticator)
	logger.Debug("Selected authenticator: ", log.String("authenticator", authr.GetName()))

	// Check if the session data is already stored with a session data key.
	sessionDataKey := ctx.SessionDataKey
	sessionDataStore := sessionstore.GetSessionDataStore()
	ok, sessionData := sessionDataStore.GetSession(sessionDataKey)
	if !ok {
		http.Error(w, "Session data not found for session data key", http.StatusBadRequest)
		return
	}

	sessionData.CurrentAuthenticator = authr.GetName()

	// Store session data in the session store. This replaces the old session data with the new one.
	sessionDataStore.AddSession(ctx.SessionDataKey, sessionData)

	err := authr.Process(w, r, ctx)
	if err != nil {
		utils.RedirectToErrorPage(w, r, oauthconstants.ErrorServerError,
			"Failed to process authentication request")
	}
}

// HandleAuthenticationRequest handles the authentication request received.
func (ah *AuthenticationHandler) HandleAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthenticationHandler"))
	logger.Info("Handling authentication request.")

	var sessionDataKey, state string
	if r.Method == http.MethodGet {
		logger.Debug("Processing GET request received for authentication flow endpoint.")

		// Extract session data key from the query parameters.
		sessionDataKey = r.URL.Query().Get(oauthconstants.SessionDataKey)
		state = r.URL.Query().Get(oauthconstants.State)
	} else {
		logger.Debug("Processing POST request received for authentication flow endpoint.")

		// Parse form data.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Extract session data key from the form data.
		sessionDataKey = r.FormValue(oauthconstants.SessionDataKey)
		state = r.FormValue(oauthconstants.State)
	}

	if sessionDataKey == "" {
		if state == "" {
			http.Error(w, "Session data key or state parameter not found", http.StatusBadRequest)
			return
		}

		logger.Info("Extracting session data key from state parameter.")

		// Extract session data key from the state parameter for federated flows.
		sessionDataKey = strings.Split(state, ",")[0]
		if sessionDataKey == "" {
			logger.Error("Session data key not found in state parameter.")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}
	}

	// Check if the session data is already stored with a session data key.
	logger.Info("Retrieving session data for session data key", log.String("sessionDataKey", sessionDataKey))
	sessionDataStore := sessionstore.GetSessionDataStore()
	ok, sessionData := sessionDataStore.GetSession(sessionDataKey)
	if !ok {
		logger.Error("Session data not found for session data key", log.String("sessionDataKey", sessionDataKey))
		http.Error(w, "Session data not found for session data key", http.StatusBadRequest)
		return
	}

	// Check for the current authenticator in the session data.
	if sessionData.CurrentAuthenticator == "" {
		logger.Error("Current authenticator not found in session data.")
		http.Error(w, "Current authenticator not found in session data", http.StatusBadRequest)
		return
	}
	authr := getAuthenticator(sessionData.CurrentAuthenticator)
	logger.Debug("Selected authenticator", log.String("authenticator", authr.GetName()))

	// Create a new session data object.
	newSessionDataKey := sessionutils.GenerateNewSessionDataKey()
	newSessionData := &sessionmodel.SessionData{
		OAuthParameters: oauthmodel.OAuthParameters{
			SessionDataKey: newSessionDataKey,
			ClientID:       sessionData.OAuthParameters.ClientID,
			RedirectURI:    sessionData.OAuthParameters.RedirectURI,
			Scopes:         sessionData.OAuthParameters.Scopes,
			State:          sessionData.OAuthParameters.State,
		},
		AuthTime:             time.Now(),
		CurrentAuthenticator: authr.GetName(),
	}

	// Create the authentication context.
	authCtx := authnmodel.AuthenticationContext{}
	authCtx.SessionDataKey = newSessionDataKey

	// Remove the old session data from the session store and add the new entry.
	sessionDataStore.ClearSession(sessionDataKey)
	sessionDataStore.AddSession(newSessionDataKey, *newSessionData)

	// Handle the authentication request with the selected authenticator.
	err := authr.Process(w, r, &authCtx)
	if err != nil {
		http.Error(w, "Failed to process authentication request", http.StatusInternalServerError)
		return
	}

	// Store session data in the session store. This replaces the old session data with the new one.
	newSessionData.AuthenticatedUser = authCtx.AuthenticatedUser
	newSessionData.AuthTime = authCtx.AuthTime
	sessionDataStore.AddSession(authCtx.SessionDataKey, *newSessionData)

	// Construct the redirect URI with the new session data key.
	redirectURI := "https://localhost:8090/oauth2/authorize"
	queryParams := map[string]string{
		"sessionDataKey": newSessionDataKey,
	}
	redirectURI, err = systemutils.GetURIWithQueryParams(redirectURI, queryParams)
	if err != nil {
		http.Error(w, "Failed to construct redirect URI", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// getAuthenticator retrieves the authenticator based on the provided name.
func getAuthenticator(authrName string) outboundauth.AuthenticatorInterface {
	// If the authenticator is not specified, use the default authenticator.
	if authrName == "" {
		authrName = config.GetThunderRuntime().Config.Authenticator.DefaultAuthenticator
	}

	switch authrName {
	case "BasicAuthenticator":
		return basicauth.NewBasicAuthenticator(getAuthenticatorConfig(authrName))
	case "GithubAuthenticator":
		return github.NewGithubAuthenticator(getAuthenticatorConfig(authrName))
	default:
		return basicauth.NewBasicAuthenticator(getAuthenticatorConfig("BasicAuthenticator"))
	}
}

// getAuthenticatorConfig retrieves the configuration for the specified authenticator.
func getAuthenticatorConfig(authrName string) *config.Authenticator {
	authConfig := config.GetThunderRuntime().Config.Authenticator
	authenticators := authConfig.Authenticators

	for _, authenticator := range authenticators {
		if authenticator.Name == authrName {
			return &authenticator
		}
	}

	if authrName == "BasicAuthenticator" {
		return &config.Authenticator{
			Name:        "BasicAuthenticator",
			DisplayName: "Username & Password",
			ID:          "123e4567-e89b-12d3-a456-426614174000",
			Type:        "local",
		}
	}

	return nil
}
