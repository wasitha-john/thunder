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

// Package abstract provides the base implementation for authenticators.
package abstract

import (
	"net/http"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/outboundauth/model"
	"github.com/asgardeo/thunder/internal/system/config"
)

// AbstractAuthenticator provides a base implementation for authenticators.
type AbstractAuthenticator struct {
	authenticatorConfig *model.AuthenticatorConfig
}

// NewAbstractAuthenticator creates a new instance of AbstractAuthenticator.
func NewAbstractAuthenticator(config *config.Authenticator) *AbstractAuthenticator {
	return &AbstractAuthenticator{
		authenticatorConfig: &model.AuthenticatorConfig{
			Name:        config.Name,
			ID:          config.ID,
			DisplayName: config.DisplayName,
			Description: config.Description,
		},
	}
}

// Process processes the authentication request to the authenticator.
func (a *AbstractAuthenticator) Process(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	if a.IsInitialRequest(r, ctx) {
		return a.InitiateAuthenticationRequest(w, r, ctx)
	}
	return a.ProcessAuthenticationResponse(w, r, ctx)
}

// InitiateAuthenticationRequest initiates the authentication request to the authenticator.
func (a *AbstractAuthenticator) InitiateAuthenticationRequest(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	return nil
}

// ProcessAuthenticationResponse processes the authentication response from the authenticator.
func (a *AbstractAuthenticator) ProcessAuthenticationResponse(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	return nil
}

// IsInitialRequest checks if the request is the initial request to the authenticator.
func (a *AbstractAuthenticator) IsInitialRequest(r *http.Request, ctx *authnmodel.AuthenticationContext) bool {
	return false
}

// GetAuthenticatorConfig returns the authenticator configuration.
func (a *AbstractAuthenticator) GetAuthenticatorConfig() model.AuthenticatorConfig {
	return *a.authenticatorConfig
}

// GetName returns the name of the authenticator.
func (a *AbstractAuthenticator) GetName() string {
	return a.authenticatorConfig.Name
}

// GetFriendlyName returns the friendly name of the authenticator.
func (a *AbstractAuthenticator) GetFriendlyName() string {
	return a.authenticatorConfig.DisplayName
}
