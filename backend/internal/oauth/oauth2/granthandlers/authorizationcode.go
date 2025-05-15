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
	"time"

	appmodel "github.com/asgardeo/thunder/internal/application/model"
	"github.com/asgardeo/thunder/internal/oauth/jwt"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz"
	authzconstants "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/constants"
	authzmodel "github.com/asgardeo/thunder/internal/oauth/oauth2/authz/model"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/oauth/oauth2/model"
)

// AuthorizationCodeGrantHandler handles the authorization code grant type.
type AuthorizationCodeGrantHandler struct{}

// ValidateGrant validates the authorization code grant request.
func (h *AuthorizationCodeGrantHandler) ValidateGrant(tokenRequest *model.TokenRequest) *model.ErrorResponse {
	if tokenRequest.GrantType == "" {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Missing grant type",
		}
	}
	if tokenRequest.GrantType != constants.GrantTypeAuthorizationCode {
		return &model.ErrorResponse{
			Error:            constants.ErrorUnsupportedGrantType,
			ErrorDescription: "Unsupported grant type",
		}
	}
	if tokenRequest.Code == "" {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Authorization code is required",
		}
	}
	if tokenRequest.ClientID == "" {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidClient,
			ErrorDescription: "Client Id is required",
		}
	}

	// TODO: Redirect uri is not mandatory when excluded in the authorize request and is valid scenario.
	//  This should be removed when supporting other means of authorization.
	if tokenRequest.RedirectURI == "" {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Redirect URI is required",
		}
	}

	return nil
}

// HandleGrant processes the authorization code grant request and generates a token response.
func (h *AuthorizationCodeGrantHandler) HandleGrant(tokenRequest *model.TokenRequest,
	oauthApp *appmodel.OAuthApplication) (*model.TokenResponse, *model.ErrorResponse) {
	// Validate the client credentials.
	// TODO: Authentication may not be required for public clients if not specified in the request.
	if tokenRequest.ClientID != oauthApp.ClientID || tokenRequest.ClientSecret != oauthApp.ClientSecret {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidClient,
			ErrorDescription: "Invalid client credentials",
		}
	}

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

	// Validate the retrieved authorization code.
	errResponse := validateAuthorizationCode(tokenRequest, authCode)
	if errResponse != nil && errResponse.Error != "" {
		return nil, errResponse
	}

	// Invalidate the authorization code after use.
	err = authz.DeactivateAuthorizationCode(authCode)
	if err != nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to invalidate authorization code",
		}
	}

	// Generate a JWT token for the client.
	token, err := jwt.GenerateJWT(tokenRequest.ClientID)
	if err != nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}

	// Return the token response.
	// TODO: Optionally issue a refresh token.
	return &model.TokenResponse{
		AccessToken: token,
		TokenType:   constants.TokenTypeBearer,
		Scope:       tokenRequest.Scope,
		ExpiresIn:   3600,
	}, nil
}

// validateAuthorizationCode validates the authorization code against the token request.
func validateAuthorizationCode(tokenRequest *model.TokenRequest,
	code authzmodel.AuthorizationCode) *model.ErrorResponse {
	if tokenRequest.ClientID != code.ClientID {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidClient,
			ErrorDescription: "Invalid client Id",
		}
	}

	// redirect_uri is not mandatory in certain scenarios. Should match if provided with the authorization.
	if code.RedirectURI != "" && tokenRequest.RedirectURI != code.RedirectURI {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Invalid redirect URI",
		}
	}

	if code.State == authzconstants.AuthCodeStateInactive {
		// TODO: Revoke all the tokens issued for this authorization code.

		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Inactive authorization code",
		}
	} else if code.State != authzconstants.AuthCodeStateActive {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Inactive authorization code",
		}
	}

	if code.ExpiryTime.Before(time.Now()) {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "Expired authorization code",
		}
	}

	return nil
}
