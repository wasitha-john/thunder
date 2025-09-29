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

// OAuthEndpoints represents the default OAuth endpoints for an OAuth identity provider.
type OAuthEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	LogoutEndpoint        string
	JwksEndpoint          string
}

// OAuthClientConfig holds the OAuth client configuration details.
type OAuthClientConfig struct {
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Scopes           []string
	OAuthEndpoints   OAuthEndpoints
	AdditionalParams map[string]string
}

// TokenResponse represents the token endpoint response body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
