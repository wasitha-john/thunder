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

package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/authn/oauth"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/user"
	"github.com/asgardeo/thunder/tests/mocks/authn/oauthmock"
	"github.com/asgardeo/thunder/tests/mocks/httpmock"
)

const (
	testGithubIDPID = "github_idp"
)

type GithubOAuthAuthnServiceTestSuite struct {
	suite.Suite
	mockOAuthService *oauthmock.OAuthAuthnServiceInterfaceMock
	mockHTTPClient   *httpmock.HTTPClientInterfaceMock
	service          GithubOAuthAuthnServiceInterface
}

func TestGithubOAuthAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(GithubOAuthAuthnServiceTestSuite))
}

func (suite *GithubOAuthAuthnServiceTestSuite) SetupTest() {
	suite.mockOAuthService = oauthmock.NewOAuthAuthnServiceInterfaceMock(suite.T())
	suite.mockHTTPClient = httpmock.NewHTTPClientInterfaceMock(suite.T())

	service := &githubOAuthAuthnService{
		internal:   suite.mockOAuthService,
		httpClient: suite.mockHTTPClient,
	}
	suite.service = service
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestBuildAuthorizeURLSuccess() {
	expectedURL := "https://github.com/login/oauth/authorize?client_id=test"
	suite.mockOAuthService.On("BuildAuthorizeURL", testGithubIDPID).Return(expectedURL, nil)

	url, err := suite.service.BuildAuthorizeURL(testGithubIDPID)
	suite.Nil(err)
	suite.Equal(expectedURL, url)
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestBuildAuthorizeURLError() {
	svcErr := &serviceerror.ServiceError{
		Code:             "ERROR",
		ErrorDescription: "Failed to build URL",
	}
	suite.mockOAuthService.On("BuildAuthorizeURL", testGithubIDPID).Return("", svcErr)

	url, err := suite.service.BuildAuthorizeURL(testGithubIDPID)
	suite.Empty(url)
	suite.NotNil(err)
	suite.Equal(svcErr.Code, err.Code)
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestExchangeCodeForTokenSuccess() {
	code := "auth_code"
	tokenResp := &oauth.TokenResponse{
		AccessToken: "access_token",
		TokenType:   "Bearer",
	}
	suite.mockOAuthService.On("ExchangeCodeForToken", testGithubIDPID, code, false).Return(tokenResp, nil)

	result, err := suite.service.ExchangeCodeForToken(testGithubIDPID, code, false)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(tokenResp.AccessToken, result.AccessToken)
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestExchangeCodeForTokenError() {
	code := "auth_code"
	svcErr := &serviceerror.ServiceError{
		Code:             "TOKEN_ERROR",
		ErrorDescription: "Failed to exchange token",
	}
	suite.mockOAuthService.On("ExchangeCodeForToken", testGithubIDPID, code, false).Return(nil, svcErr)

	result, err := suite.service.ExchangeCodeForToken(testGithubIDPID, code, false)
	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(svcErr.Code, err.Code)
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestFetchUserInfoSuccess() {
	accessToken := "access_token"
	userInfo := map[string]interface{}{
		"id":    float64(12345),
		"login": "testuser",
		"email": "test@example.com",
	}

	config := &oauth.OAuthClientConfig{
		Scopes: []string{"user", "user:email"},
		OAuthEndpoints: oauth.OAuthEndpoints{
			UserInfoEndpoint: UserInfoEndpoint,
		},
	}

	suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).Return(config, nil)
	suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, accessToken).
		Return(userInfo, nil)

	result, err := suite.service.FetchUserInfo(testGithubIDPID, accessToken)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("12345", result["sub"])
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestFetchUserInfoSuccessWithEmailFetch() {
	accessToken := "access_token"
	userInfo := map[string]interface{}{
		"id":    float64(12345),
		"login": "testuser",
	}
	emailData := []map[string]interface{}{
		{
			"email":    "test@example.com",
			"primary":  true,
			"verified": true,
		},
	}
	emailJSON, _ := json.Marshal(emailData)

	config := &oauth.OAuthClientConfig{
		Scopes: []string{"user:email"},
		OAuthEndpoints: oauth.OAuthEndpoints{
			UserInfoEndpoint: UserInfoEndpoint,
		},
	}

	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(emailJSON)),
	}

	suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).Return(config, nil)
	suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, accessToken).Return(userInfo, nil)
	suite.mockHTTPClient.On("Do", mock.Anything).Return(resp, nil)

	result, err := suite.service.FetchUserInfo(testGithubIDPID, accessToken)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("test@example.com", result["email"])
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestFetchUserInfoWithFailure() {
	testCases := []struct {
		name      string
		setupMock func()
		errCode   string
	}{
		{
			name: "ConfigRetrievalFailure",
			setupMock: func() {
				suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).
					Return(nil, &serviceerror.ServiceError{Code: "CONFIG-001"}).Once()
			},
			errCode: "CONFIG-001",
		},
		{
			name: "UserInfoFetchFailure",
			setupMock: func() {
				config := &oauth.OAuthClientConfig{
					Scopes: []string{"user"},
					OAuthEndpoints: oauth.OAuthEndpoints{
						UserInfoEndpoint: UserInfoEndpoint,
					},
				}
				suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).
					Return(config, nil).Once()
				suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, "access_token").
					Return(nil, &serviceerror.ServiceError{Code: "FETCH-001"}).Once()
			},
			errCode: "FETCH-001",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			tc.setupMock()

			result, err := suite.service.FetchUserInfo(testGithubIDPID, "access_token")
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.errCode, err.Code)
		})
	}
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestFetchUserInfoWithEmailFetchFailure() {
	testCases := []struct {
		name      string
		setupMock func()
		errCode   string
	}{
		{
			name: "EmailFetchHTTPError",
			setupMock: func() {
				userInfo := map[string]interface{}{
					"id":    float64(12345),
					"login": "testuser",
				}
				config := &oauth.OAuthClientConfig{
					Scopes: []string{"user:email"},
					OAuthEndpoints: oauth.OAuthEndpoints{
						UserInfoEndpoint: UserInfoEndpoint,
					},
				}

				suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).
					Return(config, nil).Once()
				suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, "access_token").
					Return(userInfo, nil).Once()
				suite.mockHTTPClient.On("Do", mock.Anything).
					Return(nil, errors.New("http error")).Once()
			},
			errCode: oauth.ErrorUnexpectedServerError.Code,
		},
		{
			name: "EmailFetchNon200Status",
			setupMock: func() {
				userInfo := map[string]interface{}{
					"id":    float64(12345),
					"login": "testuser",
				}
				config := &oauth.OAuthClientConfig{
					Scopes: []string{"user:email"},
					OAuthEndpoints: oauth.OAuthEndpoints{
						UserInfoEndpoint: UserInfoEndpoint,
					},
				}

				resp := &http.Response{
					StatusCode: 403,
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"error":"forbidden"}`))),
				}

				suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).
					Return(config, nil).Once()
				suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, "access_token").
					Return(userInfo, nil).Once()
				suite.mockHTTPClient.On("Do", mock.Anything).Return(resp, nil).Once()
			},
			errCode: oauth.ErrorUnexpectedServerError.Code,
		},
		{
			name: "EmailFetchInvalidJSON",
			setupMock: func() {
				userInfo := map[string]interface{}{
					"id":    float64(12345),
					"login": "testuser",
				}
				config := &oauth.OAuthClientConfig{
					Scopes: []string{"user:email"},
					OAuthEndpoints: oauth.OAuthEndpoints{
						UserInfoEndpoint: UserInfoEndpoint,
					},
				}

				resp := &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(`invalid json`))),
				}

				suite.mockOAuthService.On("GetOAuthClientConfig", testGithubIDPID).
					Return(config, nil).Once()
				suite.mockOAuthService.On("FetchUserInfoWithClientConfig", config, "access_token").
					Return(userInfo, nil).Once()
				suite.mockHTTPClient.On("Do", mock.Anything).Return(resp, nil).Once()
			},
			errCode: oauth.ErrorUnexpectedServerError.Code,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			tc.setupMock()

			result, err := suite.service.FetchUserInfo(testGithubIDPID, "access_token")
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.errCode, err.Code)
		})
	}
}

func (suite *GithubOAuthAuthnServiceTestSuite) TestGetInternalUserSuccess() {
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

func (suite *GithubOAuthAuthnServiceTestSuite) TestGetInternalUserError() {
	sub := "user123"
	svcErr := &serviceerror.ServiceError{
		Code:             "USER_NOT_FOUND",
		ErrorDescription: "User not found",
	}
	suite.mockOAuthService.On("GetInternalUser", sub).Return(nil, svcErr)

	result, err := suite.service.GetInternalUser(sub)
	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(svcErr.Code, err.Code)
}
