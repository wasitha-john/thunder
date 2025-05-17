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
	authrmodel "github.com/asgardeo/thunder/internal/outboundauth/model"
	"github.com/asgardeo/thunder/internal/system/config"
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
	// Handle the authentication request with the selected authenticator.
	authr := getDefaultAuthenticator()

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
	// Parse form data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}
	sessionDataKey := r.FormValue("sessionDataKey")

	// Check if the session data is already stored with a session data key.
	sessionDataStore := sessionstore.GetSessionDataStore()
	ok, sessionData := sessionDataStore.GetSession(sessionDataKey)
	if !ok {
		http.Error(w, "Session data not found for session data key", http.StatusBadRequest)
		return
	}

	authr := getDefaultAuthenticator()

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

// getDefaultAuthenticator retrieves the configured default authenticator.
func getDefaultAuthenticator() outboundauth.AuthenticatorInterface {
	authConfig := config.GetThunderRuntime().Config.Authenticator
	defaultAuthenticator := authConfig.DefaultAuthenticator

	switch defaultAuthenticator.Name {
	case "BasicAuthenticator":
		return basicauth.NewBasicAuthenticator(
			&authrmodel.AuthenticatorConfig{
				Name:        defaultAuthenticator.Name,
				DisplayName: defaultAuthenticator.DisplayName,
				ID:          defaultAuthenticator.ID,
				Type:        defaultAuthenticator.Type,
			},
		)
	default:
		return basicauth.NewBasicAuthenticator(
			&authrmodel.AuthenticatorConfig{
				Name:        "BasicAuthenticator",
				DisplayName: "Username & Password",
				ID:          "123e4567-e89b-12d3-a456-426614174000",
				Type:        "local",
			},
		)
	}
}
