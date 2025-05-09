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

package utils

import (
	"errors"
	"time"

	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	"github.com/google/uuid"
)

// GetAuthorizationCode generates an authorization code based on the provided OAuth message.
func GetAuthorizationCode(oAuthMessage *model.OAuthMessage) (model.AuthorizationCode, error) {

	sessionData := oAuthMessage.SessionData

	clientId := sessionData.OAuthParameters.ClientId
	if clientId == "" {
		clientId = oAuthMessage.RequestQueryParams["client_id"]
	}
	redirectUri := sessionData.OAuthParameters.RedirectUri
	if redirectUri == "" {
		redirectUri = oAuthMessage.RequestQueryParams["redirect_uri"]
	}

	if clientId == "" || redirectUri == "" {
		return model.AuthorizationCode{}, errors.New("client_id or redirect_uri is missing")
	}

	authUserId := sessionData.LoggedInUser.UserId
	if authUserId == "" {
		return model.AuthorizationCode{}, errors.New("authenticated user not found")
	}

	authTime := sessionData.AuthTime
	if authTime.IsZero() {
		return model.AuthorizationCode{}, errors.New("authentication time is not set")
	}

	scope := sessionData.OAuthParameters.Scopes
	if scope == "" {
		scope = oAuthMessage.RequestQueryParams["scope"]
	}

	// TODO: Add expiry time logic.
	expiryTime := authTime.Add(10 * time.Minute)

	return model.AuthorizationCode{
		CodeId:           uuid.New().String(),
		Code:             uuid.New().String(),
		ClientId:         clientId,
		RedirectUri:      redirectUri,
		AuthorizedUserId: authUserId,
		TimeCreated:      authTime,
		ExpiryTime:       expiryTime,
		Scopes:           scope,
		State:            constants.AUTH_CODE_STATE_ACTIVE,
	}, nil
}
