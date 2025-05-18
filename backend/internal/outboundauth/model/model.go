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

// Package model defines the data structures for outbound authenticators.
package model

// AuthenticatorConfig holds the common configurations for an authenticator.
type AuthenticatorConfig struct {
	Name        string `yaml:"name"`
	ID          string `yaml:"id"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
}

// OIDCAuthenticatorConfig holds the configuration details for the OIDC authenticator.
type OIDCAuthenticatorConfig struct {
	AuthorizationEndpoint string            `yaml:"authorization_endpoint"`
	TokenEndpoint         string            `yaml:"token_endpoint"`
	UserInfoEndpoint      string            `yaml:"userinfo_endpoint"`
	LogoutEndpoint        string            `yaml:"logout_endpoint"`
	ClientID              string            `yaml:"client_id"`
	ClientSecret          string            `yaml:"client_secret"`
	RedirectURI           string            `yaml:"redirect_uri"`
	Scopes                []string          `yaml:"scopes"`
	AdditionalParams      map[string]string `yaml:"additional_params"`
	Properties            map[string]string `yaml:"properties"`
}
