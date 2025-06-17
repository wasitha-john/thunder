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
	"encoding/json"
	"errors"
	"net/http"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	authnutils "github.com/asgardeo/thunder/internal/authn/utils"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/outboundauth/abstract"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
	userprovider "github.com/asgardeo/thunder/internal/user/provider"
)

const loggerComponentName = "BasicAuthenticator"

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
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	// Parse form data.
	if err := r.ParseForm(); err != nil {
		return errors.New("failed to parse form data: " + err.Error())
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	authenticatedUser, err2 := getAuthenticatedUser(username, password, logger)
	if err2 != nil {
		logger.Error("Failed to authenticate user",
			log.String("username", log.MaskString(username)),
			log.Error(err2))
		return err2
	}

	ctx.AuthenticatedUser = *authenticatedUser
	return nil
}

// IsInitialRequest checks if the request is an initial request to the Basic Authenticator.
func (b *BasicAuthenticator) IsInitialRequest(r *http.Request, ctx *authnmodel.AuthenticationContext) bool {
	if r.FormValue("username") == "" && r.FormValue("password") == "" {
		return true
	}
	return false
}

// getAuthenticatedUser perform authentication based on the provided username and password and return authenticated user
// details.
func getAuthenticatedUser(username, password string, logger *log.Logger) (*authnmodel.AuthenticatedUser, error) {
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()

	filters := map[string]interface{}{"username": username}
	userID, err := userService.IdentifyUser(filters)
	if err != nil {
		logger.Error("Failed to identify user by username",
			log.String("username", log.MaskString(username)),
			log.Error(err))
		return nil, err
	}
	if *userID == "" {
		logger.Error("User not found for the provided username",
			log.String("username", log.MaskString(username)))
		return nil, err
	}

	user, err := userService.VerifyUser(*userID, "password", password)
	if err != nil {
		logger.Error("Failed to verify user credentials", log.String("userID", *userID), log.Error(err))
		return nil, err
	}

	var authenticatedUser authnmodel.AuthenticatedUser
	if user == nil {
		authenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	} else {
		var attrs map[string]interface{}
		if err := json.Unmarshal(user.Attributes, &attrs); err != nil {
			logger.Error("Failed to unmarshal user attributes", log.Error(err))
			return nil, err
		}
		authenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: true,
			UserID:          user.ID,
			Attributes: map[string]string{
				"email":     attrs["email"].(string),
				"firstName": attrs["firstName"].(string),
				"lastName":  attrs["lastName"].(string),
			},
		}
	}
	return &authenticatedUser, nil
}
