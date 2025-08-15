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

// Package model provides the data structures for OAuth authentication properties and responses.
package model

// BasicOAuthExecProperties holds the basic properties required for OAuth authentication.
type BasicOAuthExecProperties struct {
	ClientID         string            `json:"clientID"`
	ClientSecret     string            `json:"clientSecret"`
	RedirectURI      string            `json:"redirectURI"`
	Scopes           []string          `json:"scopes"`
	AdditionalParams map[string]string `json:"additionalParams"`
	Properties       map[string]string `json:"properties"`
}

// OAuthExecProperties holds the properties required for OAuth authentication.
type OAuthExecProperties struct {
	AuthorizationEndpoint string            `json:"authorizationEndpoint"`
	TokenEndpoint         string            `json:"tokenEndpoint"`
	UserInfoEndpoint      string            `json:"userInfoEndpoint"`
	LogoutEndpoint        string            `json:"logoutEndpoint"`
	JwksEndpoint          string            `json:"jwksEndpoint"`
	ClientID              string            `json:"clientID"`
	ClientSecret          string            `json:"clientSecret"`
	RedirectURI           string            `json:"redirectURI"`
	Scopes                []string          `json:"scopes"`
	AdditionalParams      map[string]string `json:"additionalParams"`
	Properties            map[string]string `json:"properties"`
}

// TokenResponse represents the response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}
