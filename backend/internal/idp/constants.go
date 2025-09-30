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

package idp

// IDPType represents the type of an identity provider.
type IDPType string

const (
	// IDPTypeOAuth represents an OAuth2 identity provider.
	IDPTypeOAuth IDPType = "OAUTH"
	// IDPTypeOIDC represents an OIDC identity provider.
	IDPTypeOIDC IDPType = "OIDC"
	// IDPTypeGoogle represents a Google identity provider.
	IDPTypeGoogle IDPType = "GOOGLE"
	// IDPTypeGitHub represents a GitHub identity provider.
	IDPTypeGitHub IDPType = "GITHUB"
)

// supportedIDPTypes lists all the supported identity provider types.
var supportedIDPTypes = []IDPType{
	IDPTypeOAuth,
	IDPTypeOIDC,
	IDPTypeGoogle,
	IDPTypeGitHub,
}

// supportedIDPProperties lists all the supported identity provider properties.
var supportedIDPProperties = []string{
	"client_id",
	"client_secret",
	"redirect_uri",
	"scopes",
	"authorization_endpoint",
	"token_endpoint",
	"userinfo_endpoint",
	"logout_endpoint",
	"jwks_endpoint",
	"prompt",
}
