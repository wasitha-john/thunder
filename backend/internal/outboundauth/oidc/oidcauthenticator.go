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

// Package oidc provides the implementation of the OIDC authenticator.
package oidc

import (
	"errors"
	"net/http"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/outboundauth"
	"github.com/asgardeo/thunder/internal/outboundauth/abstract"
	"github.com/asgardeo/thunder/internal/outboundauth/model"
	"github.com/asgardeo/thunder/internal/outboundauth/oidc/utils"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

// OIDCAuthenticatorInterface defines the interface for OIDC authenticators.
type OIDCAuthenticatorInterface interface {
	outboundauth.AuthenticatorInterface
	GetCallBackURL() string
	GetAuthorizationEndpoint() string
	GetTokenEndpoint() string
	GetUserInfoEndpoint() string
	GetLogoutEndpoint() string
}

// OIDCAuthenticator implements the OIDC authenticator interface.
type OIDCAuthenticator struct {
	*abstract.AbstractAuthenticator
	oidcConfig *model.OIDCAuthenticatorConfig
}

// NewOIDCAuthenticator creates a new OIDC authenticator.
func NewOIDCAuthenticator(config *config.Authenticator,
	oidcConfig *model.OIDCAuthenticatorConfig) *OIDCAuthenticator {
	return &OIDCAuthenticator{
		AbstractAuthenticator: abstract.NewAbstractAuthenticator(config),
		oidcConfig:            oidcConfig,
	}
}

// GetOIDCConfig returns the OIDC authenticator configurations.
func (o *OIDCAuthenticator) GetOIDCConfig() *model.OIDCAuthenticatorConfig {
	return o.oidcConfig
}

// GetCallBackURL returns the callback URL for the OIDC authenticator.
func (o *OIDCAuthenticator) GetCallBackURL() string {
	return o.oidcConfig.RedirectURI
}

// GetAuthorizationEndpoint returns the authorization endpoint of the OIDC authenticator.
func (o *OIDCAuthenticator) GetAuthorizationEndpoint() string {
	return o.oidcConfig.AuthorizationEndpoint
}

// GetTokenEndpoint returns the token endpoint of the OIDC authenticator.
func (o *OIDCAuthenticator) GetTokenEndpoint() string {
	return o.oidcConfig.TokenEndpoint
}

// GetUserInfoEndpoint returns the user info endpoint of the OIDC authenticator.
func (o *OIDCAuthenticator) GetUserInfoEndpoint() string {
	return o.oidcConfig.UserInfoEndpoint
}

// GetLogoutEndpoint returns the logout endpoint of the OIDC authenticator.
func (o *OIDCAuthenticator) GetLogoutEndpoint() string {
	return o.oidcConfig.LogoutEndpoint
}

// InitiateAuthenticationRequest initiates the authentication request to the OIDC authenticator.
func (o *OIDCAuthenticator) InitiateAuthenticationRequest(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OIDCAuthenticator"))
	logger.Info("Initiating authentication request to the OIDC authenticator.")

	clientID := o.GetOIDCConfig().ClientID
	redirectURI := o.GetOIDCConfig().RedirectURI
	scopes := o.GetOIDCConfig().Scopes

	sessionDataKey := ctx.SessionDataKey
	if sessionDataKey == "" {
		return errors.New("session data key not found in context")
	}

	state := utils.GetState(sessionDataKey)

	var queryParams = make(map[string]string)
	queryParams[oauth2const.ClientID] = clientID
	queryParams[oauth2const.RedirectURI] = redirectURI
	queryParams[oauth2const.ResponseType] = oauth2const.Code
	queryParams[oauth2const.Scope] = utils.GetScopesString(scopes)
	queryParams[oauth2const.State] = state

	// append any configured additional parameters as query params.
	additionalParams := o.GetOIDCConfig().AdditionalParams
	if len(additionalParams) > 0 {
		for key, value := range additionalParams {
			if key != "" && value != "" {
				queryParams[key] = value
			}
		}
	}

	// prepare the authorization URL.
	authURL, err := systemutils.GetURIWithQueryParams(o.GetAuthorizationEndpoint(), queryParams)
	if err != nil {
		return errors.New("failed to prepare authorization URL: " + err.Error())
	}

	// redirect the user to the authorization URL.
	logger.Debug("Redirecting user to the authorization URL: " + authURL)
	http.Redirect(w, r, authURL, http.StatusFound)

	return nil
}
