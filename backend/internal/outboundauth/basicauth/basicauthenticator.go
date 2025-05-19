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

// Package basicauth provides the implementation of the Basic Authenticator.
package basicauth

import (
	"errors"
	"net/http"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	authnutils "github.com/asgardeo/thunder/internal/authn/utils"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/outboundauth/abstract"
	"github.com/asgardeo/thunder/internal/system/config"
)

// BasicAuthenticator is an implementation of the Authenticator interface for Basic Authentication.
type BasicAuthenticator struct {
	*abstract.AbstractAuthenticator
}

// NewBasicAuthenticator creates a new Basic Authenticator.
func NewBasicAuthenticator(config *config.Authenticator) *BasicAuthenticator {
	return &BasicAuthenticator{
		AbstractAuthenticator: abstract.NewAbstractAuthenticator(config),
	}
}

// Process processes the authentication request to the Basic Authenticator.
func (b *BasicAuthenticator) Process(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	if b.IsInitialRequest(r, ctx) {
		return b.InitiateAuthenticationRequest(w, r, ctx)
	}
	return b.ProcessAuthenticationResponse(w, r, ctx)
}

// InitiateAuthenticationRequest initiates the authentication request to the Basic Authenticator.
func (b *BasicAuthenticator) InitiateAuthenticationRequest(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	queryParams := ctx.RequestQueryParams

	// Append required query parameters to the redirect URI.
	loginPageURI, err := authnutils.GetLoginPageRedirectURI(queryParams)
	if err != nil {
		authnutils.RedirectToErrorPage(w, r, oauth2const.ErrorServerError,
			"Failed to redirect to login page")
	} else {
		// Redirect user-agent to the login page.
		http.Redirect(w, r, loginPageURI, http.StatusFound)
	}

	return nil
}

// ProcessAuthenticationResponse processes the authentication response from the Basic Authenticator.
func (b *BasicAuthenticator) ProcessAuthenticationResponse(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	// Parse form data.
	if err := r.ParseForm(); err != nil {
		return errors.New("failed to parse form data: " + err.Error())
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Read the valid username and password from the configuration.
	config := config.GetThunderRuntime().Config
	validUsername := config.UserStore.DefaultUser.Username
	validPassword := config.UserStore.DefaultUser.Password

	if username == validUsername && password == validPassword {
		ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
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
		ctx.AuthTime = time.Now()
	} else {
		ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	return nil
}

// IsInitialRequest checks if the request is an initial request to the Basic Authenticator.
func (b *BasicAuthenticator) IsInitialRequest(r *http.Request, ctx *authnmodel.AuthenticationContext) bool {
	if r.FormValue("username") == "" && r.FormValue("password") == "" {
		return true
	}
	return false
}
