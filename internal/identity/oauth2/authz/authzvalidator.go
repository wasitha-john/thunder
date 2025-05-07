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
	"github.com/asgardeo/thunder/internal/identity/oauth2/authz/model"
	"github.com/asgardeo/thunder/internal/identity/oauth2/constants"
)

type AuthorizationValidator struct{}

func (av *AuthorizationValidator) ValidateInitialAuthorizationRequest(
	oAuthMessage *model.OAuthMessage) (string, string) {

	// Extract required parameters.
	responseType := oAuthMessage.RequestQueryParams[constants.RESPONSE_TYPE]
	clientId := oAuthMessage.RequestQueryParams[constants.CLIENT_ID]
	redirectUri := oAuthMessage.RequestQueryParams[constants.REDIRECT_URI]
	// scope := oAuthMessage.RequestQueryParams[constants.SCOPE]
	// state := oAuthMessage.RequestQueryParams[constants.STATE]

	// Validate the authorization request.
	if responseType == "" {
		return constants.ERROR_INVALID_REQUEST, "Missing response_type parameter"
	}
	if responseType != constants.RESPONSE_TYPE_CODE {
		return constants.ERROR_UNSUPPORTED_RESPONSE_TYPE, "Unsupported response type"
	}
	if clientId == "" {
		return constants.ERROR_INVALID_REQUEST, "Missing client_id parameter"
	}
	if redirectUri == "" {
		return constants.ERROR_INVALID_REQUEST, "Missing redirect_uri parameter"
	}

	return "", ""
}
