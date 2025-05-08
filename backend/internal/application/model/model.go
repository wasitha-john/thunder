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

package model

type OAuthApplication struct {
	ClientId          string
	ClientSecret      string
	RedirectURIs      []string
	AllowedGrantTypes []string
}

// IsAllowedResponseType checks if the provided grant type is allowed.
func (o *OAuthApplication) IsAllowedGrantType(grantType string) bool {

	for _, allowedGrantType := range o.AllowedGrantTypes {
		if grantType == allowedGrantType {
			return true
		}
	}
	return false
}

// IsValidRedirectURI checks if the provided redirect URI is valid.
func (o *OAuthApplication) IsValidRedirectURI(redirectURI string) bool {

	for _, allowedRedirectURI := range o.RedirectURIs {
		if redirectURI == allowedRedirectURI {
			return true
		}
	}
	return false
}
