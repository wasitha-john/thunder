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

package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	idpmodel "github.com/asgardeo/thunder/internal/idp/model"
	oauth2const "github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	sysconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	httpservice "github.com/asgardeo/thunder/internal/system/http"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// parseIDPConfig extracts the OAuth client configuration from the identity provider details.
func parseIDPConfig(idp *idpmodel.IdpDTO) *OAuthClientConfig {
	oAuthClientConfig := OAuthClientConfig{
		AdditionalParams: make(map[string]string),
	}

	var scopesRaw string
	for _, prop := range idp.Properties {
		name := strings.TrimSpace(prop.Name)
		value := strings.TrimSpace(prop.Value)

		switch name {
		case "client_id":
			oAuthClientConfig.ClientID = value
		case "client_secret":
			oAuthClientConfig.ClientSecret = value
		case "redirect_uri":
			oAuthClientConfig.RedirectURI = value
		case "scopes":
			scopesRaw = value
		case "authorization_endpoint":
			oAuthClientConfig.OAuthEndpoints.AuthorizationEndpoint = value
		case "token_endpoint":
			oAuthClientConfig.OAuthEndpoints.TokenEndpoint = value
		case "userinfo_endpoint":
			oAuthClientConfig.OAuthEndpoints.UserInfoEndpoint = value
		case "logout_endpoint":
			oAuthClientConfig.OAuthEndpoints.LogoutEndpoint = value
		case "jwks_endpoint":
			oAuthClientConfig.OAuthEndpoints.JwksEndpoint = value
		default:
			if value != "" {
				oAuthClientConfig.AdditionalParams[name] = value
			}
		}
	}

	if scopesRaw != "" {
		oAuthClientConfig.Scopes = sysutils.ParseStringArray(scopesRaw, ",")
		if len(oAuthClientConfig.Scopes) == 1 && strings.Contains(scopesRaw, " ") &&
			!strings.Contains(scopesRaw, ",") {
			oAuthClientConfig.Scopes = sysutils.ParseStringArray(scopesRaw, " ")
		}
	}

	return &oAuthClientConfig
}

// buildTokenRequest constructs the HTTP request to exchange the authorization code for tokens.
func buildTokenRequest(oAuthClientConfig *OAuthClientConfig, code string, logger *log.Logger) (
	*http.Request, *serviceerror.ServiceError) {
	form := url.Values{}
	form.Set(oauth2const.RequestParamClientID, oAuthClientConfig.ClientID)
	form.Set(oauth2const.RequestParamClientSecret, oAuthClientConfig.ClientSecret)
	form.Set(oauth2const.RequestParamRedirectURI, oAuthClientConfig.RedirectURI)
	form.Set(oauth2const.RequestParamGrantType, string(oauth2const.GrantTypeAuthorizationCode))
	form.Set(oauth2const.RequestParamCode, code)

	httpReq, err := http.NewRequest(http.MethodPost, oAuthClientConfig.OAuthEndpoints.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		logger.Error("Failed to create token request", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}

	httpReq.Header.Add(sysconst.ContentTypeHeaderName, sysconst.ContentTypeFormURLEncoded)
	httpReq.Header.Add(sysconst.AcceptHeaderName, sysconst.ContentTypeJSON)

	return httpReq, nil
}

// sendTokenRequest sends the token request to the identity provider and processes the response.
func sendTokenRequest(httpReq *http.Request, httpClient httpservice.HTTPClientInterface, logger *log.Logger) (
	*TokenResponse, *serviceerror.ServiceError) {
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		logger.Error("Token request to identity provider failed", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close token response body", log.Error(closeErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		logger.Error("Token endpoint returned an error response",
			log.Int("statusCode", resp.StatusCode), log.String("response", string(body)))
		return nil, &ErrorUnexpectedServerError
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Error("Failed to parse token response", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}

	return &tokenResp, nil
}

// buildUserInfoRequest constructs the HTTP request to fetch user information from the identity provider.
func buildUserInfoRequest(userInfoEndpoint string, accessToken string, logger *log.Logger) (
	*http.Request, *serviceerror.ServiceError) {
	req, err := http.NewRequest(http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		logger.Error("Failed to create userinfo request", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}

	req.Header.Set(sysconst.AuthorizationHeaderName, sysconst.TokenTypeBearer+" "+accessToken)
	req.Header.Set(sysconst.AcceptHeaderName, sysconst.ContentTypeJSON)

	return req, nil
}

// sendUserInfoRequest sends the user info request to the identity provider and processes the response.
func sendUserInfoRequest(httpReq *http.Request, httpClient httpservice.HTTPClientInterface, logger *log.Logger) (
	map[string]interface{}, *serviceerror.ServiceError) {
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		logger.Error("Userinfo request to identity provider failed", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close userinfo response body", log.Error(closeErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		logger.Error("Userinfo endpoint returned an error response",
			log.Int("statusCode", resp.StatusCode), log.String("response", string(body)))
		return nil, &ErrorUnexpectedServerError
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read userinfo response body", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		logger.Error("Failed to parse userinfo response", log.Error(err))
		return nil, &ErrorUnexpectedServerError
	}

	return userInfo, nil
}

// ProcessSubClaim validates and processes the 'sub' claim in the user info.
func ProcessSubClaim(userInfo map[string]interface{}) {
	if len(userInfo) == 0 {
		return
	}
	sub := GetUserClaimValue(userInfo, "sub")
	if sub != "" {
		return
	}

	id := GetUserClaimValue(userInfo, "id")
	if id != "" {
		userInfo["sub"] = id
		delete(userInfo, "id")
		return
	}
}

// GetUserClaimValue retrieves a string claim value from the user info map.
func GetUserClaimValue(userInfo map[string]interface{}, claim string) string {
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
