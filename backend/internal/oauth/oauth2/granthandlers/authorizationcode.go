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

package granthandlers

import (
	appmodel "github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/oauth/jwt"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/model"
)

// AuthorizationCodeGrantHandler handles the authorization code grant type.
type AuthorizationCodeGrantHandler struct{}

// ValidateGrant validates the authorization code grant request.
func (h *AuthorizationCodeGrantHandler) ValidateGrant(tokenRequest *model.TokenRequest) *model.ErrorResponse {
	return nil
}

// HandleGrant processes the authorization code grant request and generates a token response.
func (h *AuthorizationCodeGrantHandler) HandleGrant(tokenRequest *model.TokenRequest,
	oauthApp *appmodel.OAuthApplication) (*model.TokenResponse, *model.ErrorResponse) {
	// TODO: Validate error responses according to spec.
	// Validate the authorization code.
	if tokenRequest.Code == "" {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidClient,
			ErrorDescription: "Authorization code is required",
		}
	}

	authCode, err := authz.GetAuthorizationCode(tokenRequest.ClientID, tokenRequest.Code)
	if err != nil || authCode.Code == "" {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Invalid authorization code",
		}
	}

	// TODO: Validate auth code params.

	// Generate a JWT token for the client.
	token, err := jwt.GenerateJWT(authCode.AuthorizedUserID, authCode.ClientID)
	if err != nil {
		// TODO: Need to validate the error type and return appropriate error response.
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}

	// Return the token response.
	return &model.TokenResponse{
		AccessToken: token,
		TokenType:   constants.TokenTypeBearer,
		Scope:       tokenRequest.Scope,
		ExpiresIn:   3600,
	}, nil
}
