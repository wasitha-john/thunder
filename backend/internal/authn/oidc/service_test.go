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

package oidc

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/authn/oauth"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/user"
	"github.com/asgardeo/thunder/tests/mocks/authn/oauthmock"
	"github.com/asgardeo/thunder/tests/mocks/jwtmock"
)

const (
	testOIDCIDPID = "idp123"
)

type OIDCAuthnServiceTestSuite struct {
	suite.Suite
	mockOAuthService *oauthmock.OAuthAuthnServiceInterfaceMock
	mockJWTService   *jwtmock.JWTServiceInterfaceMock
	service          OIDCAuthnServiceInterface
}

func TestOIDCAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(OIDCAuthnServiceTestSuite))
}

func (suite *OIDCAuthnServiceTestSuite) SetupTest() {
	suite.mockOAuthService = oauthmock.NewOAuthAuthnServiceInterfaceMock(suite.T())
	suite.mockJWTService = jwtmock.NewJWTServiceInterfaceMock(suite.T())
	suite.service = NewOIDCAuthnService(suite.mockOAuthService, suite.mockJWTService)
}

func (suite *OIDCAuthnServiceTestSuite) TestGetOAuthClientConfigWithOpenIDScope() {
	idpID := testOIDCIDPID
	config := &oauth.OAuthClientConfig{
		ClientID:     "client123",
		ClientSecret: "secret",
		Scopes:       []string{"openid", "profile", "email"},
	}
	suite.mockOAuthService.On("GetOAuthClientConfig", idpID).Return(config, nil)

	result, err := suite.service.GetOAuthClientConfig(idpID)
	suite.Nil(err)
	suite.NotNil(result)

	suite.Contains(result.Scopes, "openid")
	suite.Contains(result.Scopes, "profile")
	suite.Contains(result.Scopes, "email")

	// Ensure openid is not duplicated
	suite.Equal(3, len(result.Scopes))
}

func (suite *OIDCAuthnServiceTestSuite) TestGetOAuthClientConfigWithoutOpenIDScope() {
	idpID := testOIDCIDPID
	config := &oauth.OAuthClientConfig{
		ClientID:     "client123",
		ClientSecret: "secret",
		Scopes:       []string{"profile"},
	}
	suite.mockOAuthService.On("GetOAuthClientConfig", idpID).Return(config, nil)

	result, err := suite.service.GetOAuthClientConfig(idpID)
	suite.Nil(err)
	suite.NotNil(result)

	suite.Contains(result.Scopes, "openid")
	suite.Contains(result.Scopes, "profile")
}

func (suite *OIDCAuthnServiceTestSuite) TestBuildAuthorizeURLSuccess() {
	expectedURL := "https://example.com/authorize?client_id=test"
	suite.mockOAuthService.On("BuildAuthorizeURL", testOIDCIDPID).Return(expectedURL, nil)

	url, err := suite.service.BuildAuthorizeURL(testOIDCIDPID)
	suite.Nil(err)
	suite.Equal(expectedURL, url)
}

func (suite *OIDCAuthnServiceTestSuite) TestBuildAuthorizeURLError() {
	svcErr := &serviceerror.ServiceError{
		Code:             "ERROR",
		ErrorDescription: "Failed to build URL",
	}
	suite.mockOAuthService.On("BuildAuthorizeURL", testOIDCIDPID).Return("", svcErr)

	url, err := suite.service.BuildAuthorizeURL(testOIDCIDPID)
	suite.Empty(url)
	suite.NotNil(err)
	suite.Equal(svcErr.Code, err.Code)
}

func (suite *OIDCAuthnServiceTestSuite) TestExchangeCodeForTokenSuccess() {
	tests := []struct {
		name             string
		validateResponse bool
		setupMocks       func()
	}{
		{
			name:             "WithValidation",
			validateResponse: true,
			setupMocks: func() {
				code := "auth_code"
				tokenResp := &oauth.TokenResponse{
					AccessToken: "access_token",
					IDToken:     "id_token",
					TokenType:   "Bearer",
				}
				suite.mockOAuthService.On("ExchangeCodeForToken", testOIDCIDPID, code, false).Return(tokenResp, nil)
				suite.mockOAuthService.On("GetOAuthClientConfig", testOIDCIDPID).Return(&oauth.OAuthClientConfig{
					OAuthEndpoints: oauth.OAuthEndpoints{JwksEndpoint: "https://example.com/jwks"},
				}, nil)
				suite.mockJWTService.On("VerifyJWTWithJWKS", "id_token",
					"https://example.com/jwks", "", "").Return(nil)
			},
		},
		{
			name:             "WithoutValidation",
			validateResponse: false,
			setupMocks: func() {
				code := "auth_code"
				tokenResp := &oauth.TokenResponse{
					AccessToken: "access_token",
					IDToken:     "id_token",
					TokenType:   "Bearer",
				}
				suite.mockOAuthService.On("ExchangeCodeForToken", testOIDCIDPID, code, false).Return(tokenResp, nil)
			},
		},
	}

	for _, tc := range tests {
		suite.Run(tc.name, func() {
			suite.mockOAuthService = oauthmock.NewOAuthAuthnServiceInterfaceMock(suite.T())
			suite.mockJWTService = jwtmock.NewJWTServiceInterfaceMock(suite.T())
			suite.service = NewOIDCAuthnService(suite.mockOAuthService, suite.mockJWTService)

			tc.setupMocks()

			result, err := suite.service.ExchangeCodeForToken(testOIDCIDPID, "auth_code", tc.validateResponse)
			suite.Nil(err)
			suite.NotNil(result)
			suite.Equal("access_token", result.AccessToken)
		})
	}
}

func (suite *OIDCAuthnServiceTestSuite) TestValidateTokenResponseSuccess() {
	tests := []struct {
		name            string
		validateIDToken bool
		setupMocks      func()
	}{
		{
			name:            "WithIDTokenValidation",
			validateIDToken: true,
			setupMocks: func() {
				suite.mockOAuthService.On("GetOAuthClientConfig", testOIDCIDPID).Return(&oauth.OAuthClientConfig{
					OAuthEndpoints: oauth.OAuthEndpoints{JwksEndpoint: "https://example.com/jwks"},
				}, nil)
				suite.mockJWTService.On("VerifyJWTWithJWKS", "id_token",
					"https://example.com/jwks", "", "").Return(nil)
			},
		},
		{
			name:            "WithoutIDTokenValidation",
			validateIDToken: false,
			setupMocks:      func() {},
		},
	}

	for _, tc := range tests {
		suite.Run(tc.name, func() {
			suite.mockOAuthService = oauthmock.NewOAuthAuthnServiceInterfaceMock(suite.T())
			suite.mockJWTService = jwtmock.NewJWTServiceInterfaceMock(suite.T())
			suite.service = NewOIDCAuthnService(suite.mockOAuthService, suite.mockJWTService)

			tc.setupMocks()

			tokenResp := &oauth.TokenResponse{
				AccessToken: "access_token",
				IDToken:     "id_token",
				TokenType:   "Bearer",
			}
			err := suite.service.ValidateTokenResponse(testOIDCIDPID, tokenResp, tc.validateIDToken)
			suite.Nil(err)
		})
	}
}

func (suite *OIDCAuthnServiceTestSuite) TestValidateTokenResponseWithError() {
	tests := []struct {
		name string
		resp *oauth.TokenResponse
	}{
		{
			name: "NilResponse",
			resp: nil,
		},
		{
			name: "EmptyAccessToken",
			resp: &oauth.TokenResponse{AccessToken: "", IDToken: "id_token"},
		},
		{
			name: "EmptyIDToken",
			resp: &oauth.TokenResponse{AccessToken: "access_token", IDToken: ""},
		},
	}

	for _, tc := range tests {
		suite.Run(tc.name, func() {
			err := suite.service.ValidateTokenResponse(testOIDCIDPID, tc.resp, false)
			suite.NotNil(err)
			suite.Equal(oauth.ErrorInvalidTokenResponse.Code, err.Code)
		})
	}
}

func (suite *OIDCAuthnServiceTestSuite) TestValidateIDTokenSuccess() {
	tests := []struct {
		name       string
		setupMocks func()
	}{
		{
			name: "WithJWKSEndpoint",
			setupMocks: func() {
				suite.mockOAuthService.On("GetOAuthClientConfig", testOIDCIDPID).Return(&oauth.OAuthClientConfig{
					OAuthEndpoints: oauth.OAuthEndpoints{JwksEndpoint: "https://example.com/jwks"},
				}, nil)
				suite.mockJWTService.On("VerifyJWTWithJWKS", "valid_id_token",
					"https://example.com/jwks", "", "").Return(nil)
			},
		},
		{
			name: "WithoutJWKSEndpoint",
			setupMocks: func() {
				suite.mockOAuthService.On("GetOAuthClientConfig", testOIDCIDPID).Return(&oauth.OAuthClientConfig{
					OAuthEndpoints: oauth.OAuthEndpoints{},
				}, nil)
			},
		},
	}

	for _, tc := range tests {
		suite.Run(tc.name, func() {
			suite.mockOAuthService = oauthmock.NewOAuthAuthnServiceInterfaceMock(suite.T())
			suite.mockJWTService = jwtmock.NewJWTServiceInterfaceMock(suite.T())
			suite.service = NewOIDCAuthnService(suite.mockOAuthService, suite.mockJWTService)

			tc.setupMocks()

			err := suite.service.ValidateIDToken(testOIDCIDPID, "valid_id_token")
			suite.Nil(err)
		})
	}
}

func (suite *OIDCAuthnServiceTestSuite) TestValidateIDTokenEmptyToken() {
	err := suite.service.ValidateIDToken(testOIDCIDPID, "")
	suite.NotNil(err)
	suite.Equal(ErrorInvalidIDToken.Code, err.Code)
}

func (suite *OIDCAuthnServiceTestSuite) TestGetIDTokenClaimsSuccess() {
	// Create a valid JWT token (base64 encoded header.payload.signature)
	idToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	claims, err := suite.service.GetIDTokenClaims(idToken)
	suite.Nil(err)
	suite.NotNil(claims)
	suite.Equal("1234567890", claims["sub"])
}

func (suite *OIDCAuthnServiceTestSuite) TestGetIDTokenClaimsEmptyToken() {
	claims, err := suite.service.GetIDTokenClaims("")
	suite.Nil(claims)
	suite.NotNil(err)
	suite.Equal(ErrorInvalidIDToken.Code, err.Code)
}

func (suite *OIDCAuthnServiceTestSuite) TestFetchUserInfoSuccess() {
	accessToken := "access_token"
	userInfo := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}
	suite.mockOAuthService.On("FetchUserInfo", testOIDCIDPID, accessToken).Return(userInfo, nil)

	result, err := suite.service.FetchUserInfo(testOIDCIDPID, accessToken)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(userInfo["sub"], result["sub"])
}

func (suite *OIDCAuthnServiceTestSuite) TestGetInternalUserSuccess() {
	sub := "user123"
	user := &user.User{
		ID:   "user123",
		Type: "person",
	}
	suite.mockOAuthService.On("GetInternalUser", sub).Return(user, nil)

	result, err := suite.service.GetInternalUser(sub)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(user.ID, result.ID)
}
