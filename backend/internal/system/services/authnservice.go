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

package services

import (
	"net/http"
	"time"

	oauthmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/model"
	oauthutils "github.com/asgardeo/thunder/internal/oauth/oauth2/utils"
	"github.com/asgardeo/thunder/internal/oauth/session/model"
	sessionstore "github.com/asgardeo/thunder/internal/oauth/session/store"
	"github.com/asgardeo/thunder/internal/system/config"
)

// AuthenticationService defines the service for handling authentication requests.
// This is a dummy implementation for the authentication service.
type AuthenticationService struct{}

// NewAuthenticationService creates a new instance of AuthenticationService.
func NewAuthenticationService(mux *http.ServeMux) *AuthenticationService {
	instance := &AuthenticationService{}
	instance.RegisterRoutes(mux)
	return instance
}

// RegisterRoutes registers the routes for the AuthenticationService.
func (s *AuthenticationService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /flow/authn", s.HandleAuthenticationRequest)
}

// HandleAuthenticationRequest handles the authentication request.
func (s *AuthenticationService) HandleAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	sessionDataKey := r.FormValue("sessionDataKey")

	// Check if the session data is already stored with a session data key.
	sessionDataStore := sessionstore.GetSessionDataStore()
	ok, sessionData := sessionDataStore.GetSession(sessionDataKey)
	if !ok {
		http.Error(w, "Session data not found for session data key", http.StatusBadRequest)
		return
	}

	// Read the valid username and password from the configuration.
	config := config.GetThunderRuntime().Config
	validUsername := config.UserStore.DefaultUser.Username
	validPassword := config.UserStore.DefaultUser.Password

	// Create a new session data object.
	newSessionDataKey := oauthutils.GenerateNewSessionDataKey()
	newSessionData := &model.SessionData{
		OAuthParameters: oauthmodel.OAuthParameters{
			SessionDataKey: newSessionDataKey,
			ClientID:       sessionData.OAuthParameters.ClientID,
			RedirectURI:    sessionData.OAuthParameters.RedirectURI,
			Scopes:         sessionData.OAuthParameters.Scopes,
			State:          sessionData.OAuthParameters.State,
		},
		AuthTime: time.Now(),
	}

	if username == validUsername && password == validPassword {
		newSessionData.LoggedInUser = model.AuthenticatedUser{
			IsAuthenticated:        true,
			UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
			Username:               username,
			Domain:                 "PRIMARY",
			AuthenticatedSubjectID: username + "@carbon.super",
			Attributes: map[string]string{
				"email":     "admin@wso2.com",
				"firstName": "Admin",
				"lastName":  "User",
			},
		}
	} else {
		newSessionData.LoggedInUser = model.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	// Remove the old session data from the session store and add the new entry.
	sessionDataStore.ClearSession(sessionDataKey)
	sessionDataStore.AddSession(newSessionDataKey, *newSessionData)

	// Construct the redirect URI with the new session data key.
	redirectURI := "https://localhost:8090/oauth2/authorize"
	queryParams := map[string]string{
		"sessionDataKey": newSessionDataKey,
	}
	redirectURI, err := oauthutils.GetURIWithQueryParams(redirectURI, queryParams)
	if err != nil {
		http.Error(w, "Failed to construct redirect URI", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}
