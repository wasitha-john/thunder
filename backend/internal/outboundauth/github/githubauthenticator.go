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

// Package github provides the implementation of the Github OIDC authenticator.
package github

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/outboundauth/model"
	"github.com/asgardeo/thunder/internal/outboundauth/oidc"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/constants"
	httpservice "github.com/asgardeo/thunder/internal/system/http"
	"github.com/asgardeo/thunder/internal/system/log"
)

// GithubAuthenticator implements the OIDC authenticator for Github.
type GithubAuthenticator struct {
	*oidc.OIDCAuthenticator
}

// NewGithubAuthenticator creates a new Github authenticator.
func NewGithubAuthenticator(config *config.Authenticator) *GithubAuthenticator {
	return &GithubAuthenticator{
		OIDCAuthenticator: oidc.NewOIDCAuthenticator(
			config,
			&model.OIDCAuthenticatorConfig{
				AuthorizationEndpoint: githubAuthorizeEndpoint,
				TokenEndpoint:         githubTokenEndpoint,
				UserInfoEndpoint:      githubUserInfoEndpoint,
				ClientID:              config.ClientID,
				ClientSecret:          config.ClientSecret,
				RedirectURI:           config.RedirectURI,
				Scopes:                config.Scopes,
				AdditionalParams:      config.AdditionalParams,
			},
		),
	}
}

// Process processes the authentication request to the github authenticator.
func (ga *GithubAuthenticator) Process(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	if ga.IsInitialRequest(r, ctx) {
		return ga.InitiateAuthenticationRequest(w, r, ctx)
	}
	return ga.ProcessAuthenticationResponse(w, r, ctx)
}

// ProcessAuthenticationResponse processes the authentication response from the github authenticator.
func (ga *GithubAuthenticator) ProcessAuthenticationResponse(w http.ResponseWriter, r *http.Request,
	ctx *authnmodel.AuthenticationContext) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Info("Processing authentication response from Github.")

	var code, state string
	if r.Method == http.MethodGet {
		code = r.URL.Query().Get(oauth2const.Code)
		state = r.URL.Query().Get(oauth2const.State)
	} else {
		// Parse form data.
		if err := r.ParseForm(); err != nil {
			return errors.New("failed to parse form data: " + err.Error())
		}
		code = r.FormValue(oauth2const.Code)
		state = r.FormValue(oauth2const.State)
	}

	if code == "" {
		return errors.New("code not found in the response")
	}
	if state == "" {
		return errors.New("state not found in the response")
	}

	// Exchange the code for an access token.
	data := url.Values{}
	data.Set(oauth2const.ClientID, ga.GetOIDCConfig().ClientID)
	data.Set(oauth2const.ClientSecret, ga.GetOIDCConfig().ClientSecret)
	data.Set(oauth2const.Code, code)
	data.Set(oauth2const.RedirectURI, ga.GetOIDCConfig().RedirectURI)

	req, err := http.NewRequest("POST", ga.GetTokenEndpoint(), strings.NewReader(data.Encode()))
	if err != nil {
		logger.Error("Failed to create token request: ", log.Error(err))
		return errors.New("failed to create token request: " + err.Error())
	}
	req.Header.Set(constants.ContentTypeHeaderName, "application/x-www-form-urlencoded")
	req.Header.Set(constants.AcceptHeaderName, "application/json")

	logger.Debug("Sending token request to Github.")
	client := httpservice.GetHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send token request: ", log.Error(err))
		return errors.New("failed to send token request: " + err.Error())
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error("Failed to close response body: ", log.Error(err))
		}
	}()
	logger.Debug("Token response received from Github.")

	if resp.StatusCode != http.StatusOK {
		return errors.New("token request failed with status: " + resp.Status)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		logger.Error("Failed to decode token response: ", log.Error(err))
		return errors.New("failed to decode token response: " + err.Error())
	}

	if tokenResponse.AccessToken == "" {
		logger.Debug("Access token not found in the token response.")
		return errors.New("access token not found in the response")
	}

	if tokenResponse.Scope == "" {
		logger.Info("No scopes returned in the token response")

		ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: true,
			UserID:          "550e8400-e29b-41d4-a716-446655440000",
		}
		ctx.AuthTime = time.Now()

		return nil
	}

	// Fetch user information with the access token.
	logger.Debug("Retrieving user information for the authenticated user.")
	userAttributes, err := ga.getUserInfo(logger, client, tokenResponse.AccessToken)
	if err != nil {
		logger.Error("Failed to fetch user info: ", log.Error(err))
		return errors.New("failed to fetch user info: " + err.Error())
	}

	// Set the authenticated user in the context.
	ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
		IsAuthenticated: true,
		UserID:          "550e8400-e29b-41d4-a716-446655440000",
		Attributes:      userAttributes,
	}
	ctx.AuthTime = time.Now()

	return nil
}

// IsInitialRequest checks if the request is an initial request to the github authenticator.
func (ga *GithubAuthenticator) IsInitialRequest(r *http.Request, ctx *authnmodel.AuthenticationContext) bool {
	if r.URL.Query().Get(oauth2const.Code) == "" && r.URL.Query().Get(oauth2const.Error) == "" {
		return true
	}
	return false
}

// getUserInfo fetches the user information from the user info endpoint using the access token.
func (ga *GithubAuthenticator) getUserInfo(logger *log.Logger, client httpservice.HTTPClientInterface,
	accessToken string) (map[string]string, error) {
	req, err := http.NewRequest("GET", ga.GetUserInfoEndpoint(), nil)
	if err != nil {
		logger.Error("Failed to create user info request: ", log.Error(err))
		return nil, errors.New("failed to create user info request: " + err.Error())
	}
	req.Header.Set(constants.AuthorizationHeaderName, constants.TokenTypeBearer+" "+accessToken)
	req.Header.Set(constants.AcceptHeaderName, "application/json")

	resp, err := client.Do(req)
	logger.Debug("Sending user info request to Github.")
	if err != nil {
		logger.Error("Failed to send user info request: ", log.Error(err))
		return nil, errors.New("failed to fetch user info: " + err.Error())
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error("Failed to close response body: ", log.Error(err))
		}
	}()
	logger.Debug("User info response received from Github.")

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("user info request failed with status: " + resp.Status)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		logger.Error("Failed to decode user info response: ", log.Error(err))
		return nil, errors.New("failed to decode user info response: " + err.Error())
	}

	// If the user info doesn't contain the email, but scopes contain "user" or "user:email",
	// then fetch the primary email from the email endpoint.
	email := userInfo["email"]
	scopes := ga.GetOIDCConfig().Scopes
	if (email == nil || email == "") &&
		(slices.Contains(scopes, userScope) || slices.Contains(scopes, userEmailScope)) {
		logger.Debug("Fetching user email from Github email endpoint.")
		req, err = http.NewRequest("GET", githubUserEmailEndpoint, nil)
		if err != nil {
			logger.Error("Failed to create user email request: ", log.Error(err))
			return nil, errors.New("failed to create user email request: " + err.Error())
		}
		req.Header.Set(constants.AuthorizationHeaderName, constants.TokenTypeBearer+" "+accessToken)
		req.Header.Set(constants.AcceptHeaderName, "application/json")

		resp, err = client.Do(req)
		if err != nil {
			logger.Error("Failed to send user email request: ", log.Error(err))
			return nil, errors.New("failed to fetch user email: " + err.Error())
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				logger.Error("Failed to close response body: ", log.Error(err))
			}
		}()
		logger.Debug("User email response received from Github.")

		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("user email request failed with status: " + resp.Status)
		}

		var emails []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
			logger.Error("Failed to decode email response: ", log.Error(err))
			return nil, errors.New("failed to decode email response: " + err.Error())
		}

		// Set the primary email in the user info map.
		for _, emailEntry := range emails {
			if isPrimary, ok := emailEntry["primary"].(bool); ok && isPrimary {
				if primaryEmail, ok := emailEntry["email"].(string); ok {
					userInfo["email"] = primaryEmail
					break
				}
			}
		}
	}

	// Construct and return the user attributes.
	return constructUserAttributes(userInfo), nil
}

// constructUserAttributes constructs the user attributes from the user info map.
func constructUserAttributes(userInfo map[string]interface{}) map[string]string {
	userAttributes := make(map[string]string)
	for key, value := range userInfo {
		// If the value is a string, add it to the user attributes map.
		if strValue, ok := value.(string); ok {
			userAttributes[key] = strValue
		}
		// If the value is a slice, convert it to a string and add it to the user attributes map.
		if sliceValue, ok := value.([]interface{}); ok {
			var strValue string
			for _, v := range sliceValue {
				if str, ok := v.(string); ok {
					strValue += str + ","
				}
			}
			if len(strValue) > 0 {
				strValue = strings.TrimSuffix(strValue, ",")
			}
			userAttributes[key] = strValue
		}
	}
	return userAttributes
}
