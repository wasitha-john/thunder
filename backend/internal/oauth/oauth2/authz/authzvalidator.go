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

package authz

import (
	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
)

// AuthorizationValidatorInterface defines the interface for validating OAuth2 authorization requests.
type AuthorizationValidatorInterface interface {
	validateInitialAuthorizationRequest(msg *model.OAuthMessage) (string, string)
}

// AuthorizationValidator implements the AuthorizationValidatorInterface for validating OAuth2 authorization requests.
type AuthorizationValidator struct{}

// NewAuthorizationValidator creates a new instance of AuthorizationValidator.
func NewAuthorizationValidator() AuthorizationValidatorInterface {
	return &AuthorizationValidator{}
}

// validateInitialAuthorizationRequest validates the initial authorization request parameters.
func (av *AuthorizationValidator) validateInitialAuthorizationRequest(msg *model.OAuthMessage) (string, string) {
	// Extract required parameters.
	responseType := msg.RequestQueryParams[constants.ResponseType]
	clientID := msg.RequestQueryParams[constants.ClientID]
	redirectURI := msg.RequestQueryParams[constants.RedirectURI]

	// Validate the authorization request.
	if responseType == "" {
		return constants.ErrorInvalidRequest, "Missing response_type parameter"
	}
	if responseType != constants.ResponseTypeCode {
		return constants.ErrorUnsupportedResponseType, "Unsupported response type"
	}
	if clientID == "" {
		return constants.ErrorInvalidRequest, "Missing client_id parameter"
	}
	if redirectURI == "" {
		return constants.ErrorInvalidRequest, "Missing redirect_uri parameter"
	}

	return "", ""
}
