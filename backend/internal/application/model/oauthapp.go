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

import (
	"fmt"
	"net/url"

	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// OAuthApplication represents an OAuth application details.
type OAuthApplication struct {
	ClientID          string
	ClientSecret      string
	RedirectURIs      []string
	AllowedGrantTypes []string
}

// IsAllowedGrantType checks if the provided grant type is allowed.
func (o *OAuthApplication) IsAllowedGrantType(grantType string) bool {
	for _, allowedGrantType := range o.AllowedGrantTypes {
		if grantType == allowedGrantType {
			return true
		}
	}
	return false
}

// ValidateRedirectURI validates the provided redirect URI against the registered redirect URIs.
func (o *OAuthApplication) ValidateRedirectURI(redirectURI string) error {
	logger := log.GetLogger()

	// Check if the redirect URI is empty.
	if redirectURI == "" {
		// Check if multiple redirect URIs are registered.
		if len(o.RedirectURIs) != 1 {
			return fmt.Errorf("redirect URI is required in the authorization request")
		}
		// Check if only a part of the redirect uri is registered.
		parsed, err := url.Parse(o.RedirectURIs[0])
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("registered redirect URI is not fully qualified")
		}

		// Valid scenario.
		return nil
	}

	// Check if the redirect URI is registered.
	if !o.isValidRedirectURI(redirectURI) {
		return fmt.Errorf("your application's redirect URL does not match with the registered redirect URLs")
	}

	// Parse the redirect URI.
	parsedRedirectURI, err := utils.ParseURL(redirectURI)
	if err != nil {
		logger.Error("Failed to parse redirect URI", log.Error(err))
		return fmt.Errorf("invalid redirect URI: %s", err.Error())
	}
	// Check if it is a fragment URI.
	if parsedRedirectURI.Fragment != "" {
		return fmt.Errorf("redirect URI must not contain a fragment component")
	}

	return nil
}

// isValidRedirectURI checks if the provided redirect URI is valid.
func (o *OAuthApplication) isValidRedirectURI(redirectURI string) bool {
	for _, allowedRedirectURI := range o.RedirectURIs {
		if redirectURI == allowedRedirectURI {
			return true
		}
	}
	return false
}
