/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

// Package github implements an authentication service for authentication via GitHub OAuth.

package github

import (
	"slices"
	"time"

	oauthauthn "github.com/asgardeo/thunder/internal/authn/oauth"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	syshttp "github.com/asgardeo/thunder/internal/system/http"
	"github.com/asgardeo/thunder/internal/system/log"
	usermodel "github.com/asgardeo/thunder/internal/user/model"
)

const (
	loggerComponentName = "GithubAuthnService"
	defaultHTTPTimeout  = 5 * time.Second
)

// GithubOAuthAuthnServiceInterface defines the contract for GitHub OAuth based authenticator services.
type GithubOAuthAuthnServiceInterface interface {
	BuildAuthorizeURL(idpID string) (string, *serviceerror.ServiceError)
	ExchangeCodeForToken(idpID, code string) (*oauthauthn.TokenResponse, *serviceerror.ServiceError)
	FetchUserInfo(idpID, accessToken string) (map[string]interface{}, *serviceerror.ServiceError)
	GetInternalUser(sub string) (*usermodel.User, *serviceerror.ServiceError)
}

// GithubOAuthAuthnService is the default implementation of GithubOAuthAuthnServiceInterface.
type GithubOAuthAuthnService struct {
	internal   oauthauthn.OAuthAuthnServiceInterface
	httpClient syshttp.HTTPClientInterface
}

// NewGithubOAuthAuthnService returns an OAuth authenticator service for GitHub.
func NewGithubOAuthAuthnService(oAuthSvc oauthauthn.OAuthAuthnServiceInterface,
	httpClient syshttp.HTTPClientInterface) GithubOAuthAuthnServiceInterface {
	if oAuthSvc == nil {
		oAuthSvc = oauthauthn.NewOAuthAuthnService(nil, nil, oauthauthn.OAuthEndpoints{
			AuthorizationEndpoint: AuthorizeEndpoint,
			TokenEndpoint:         TokenEndpoint,
			UserInfoEndpoint:      UserInfoEndpoint,
		})
	}
	if httpClient == nil {
		httpClient = syshttp.NewHTTPClientWithTimeout(defaultHTTPTimeout)
	}

	return &GithubOAuthAuthnService{
		internal:   oAuthSvc,
		httpClient: httpClient,
	}
}

// BuildAuthorizeURL constructs the authorization request URL for GitHub OAuth authentication.
func (g *GithubOAuthAuthnService) BuildAuthorizeURL(idpID string) (string, *serviceerror.ServiceError) {
	return g.internal.BuildAuthorizeURL(idpID)
}

// ExchangeCodeForToken exchanges the authorization code for a token with GitHub.
func (g *GithubOAuthAuthnService) ExchangeCodeForToken(idpID, code string) (*oauthauthn.TokenResponse,
	*serviceerror.ServiceError) {
	return g.internal.ExchangeCodeForToken(idpID, code)
}

// FetchUserInfo retrieves user information from the Github API, ensuring email resolution if necessary.
func (g *GithubOAuthAuthnService) FetchUserInfo(idpID, accessToken string) (
	map[string]interface{}, *serviceerror.ServiceError) {
	oAuthClientConfig, svcErr := g.internal.GetOAuthClientConfig(idpID)
	if svcErr != nil {
		return nil, svcErr
	}

	userInfo, svcErr := g.internal.FetchUserInfoWithClientConfig(oAuthClientConfig, accessToken)
	if svcErr != nil {
		return userInfo, svcErr
	}

	// If email is already present in the user info or email scope is not requested, return it directly.
	email := getUserClaimValue(userInfo, "email")
	if email != "" || !g.shouldFetchEmail(oAuthClientConfig.Scopes) {
		g.processSubClaim(userInfo)
		return userInfo, nil
	}

	// Fetch primary email from the GitHub user emails endpoint.
	primaryEmail, svcErr := g.fetchPrimaryEmail(accessToken)
	if svcErr != nil {
		return nil, svcErr
	}
	if primaryEmail != "" {
		userInfo["email"] = primaryEmail
	}

	g.processSubClaim(userInfo)
	return userInfo, nil
}

// processSubClaim validates and processes the 'sub' claim in the user info.
func (g *GithubOAuthAuthnService) processSubClaim(userInfo map[string]interface{}) {
	if len(userInfo) == 0 {
		return
	}
	sub := getUserClaimValue(userInfo, "sub")
	if sub != "" {
		return
	}

	id := getUserClaimValue(userInfo, "id")
	if id != "" {
		userInfo["sub"] = id
		delete(userInfo, "id")
		return
	}
}

// getUserClaimValue retrieves a string claim value from the user info map.
func getUserClaimValue(userInfo map[string]interface{}, claim string) string {
	if len(userInfo) == 0 {
		return ""
	}
	if val, ok := userInfo[claim]; ok {
		if valStr, ok := val.(string); ok {
			return valStr
		}
	}
	return ""
}

// shouldFetchEmail check whether user email should be fetched from the emails endpoint based on the scopes.
func (g *GithubOAuthAuthnService) shouldFetchEmail(scopes []string) bool {
	return slices.Contains(scopes, UserScope) || slices.Contains(scopes, UserEmailScope)
}

// fetchPrimaryEmail fetches the primary email of the user from the GitHub user emails endpoint.
func (g *GithubOAuthAuthnService) fetchPrimaryEmail(accessToken string) (string, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Fetching user email from GitHub user email endpoint",
		log.String("userEmailEndpoint", UserEmailEndpoint))

	req, svcErr := buildUserEmailRequest(UserEmailEndpoint, accessToken, logger)
	if svcErr != nil {
		return "", svcErr
	}

	emails, svcErr := sendUserEmailRequest(req, g.httpClient, logger)
	if svcErr != nil {
		return "", svcErr
	}

	for _, emailEntry := range emails {
		if isPrimary, ok := emailEntry["primary"].(bool); ok && isPrimary {
			if primaryEmail, ok := emailEntry["email"].(string); ok {
				return primaryEmail, nil
			}
		}
	}

	return "", nil
}

// GetInternalUser retrieves the internal user based on the external subject identifier.
func (g *GithubOAuthAuthnService) GetInternalUser(sub string) (*usermodel.User, *serviceerror.ServiceError) {
	return g.internal.GetInternalUser(sub)
}
