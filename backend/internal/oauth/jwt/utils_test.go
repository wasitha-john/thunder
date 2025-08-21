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

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/config"
)

type JWTUtilsTestSuite struct {
	suite.Suite
}

func TestJWTUtilsSuite(t *testing.T) {
	suite.Run(t, new(JWTUtilsTestSuite))
}

func (suite *JWTUtilsTestSuite) SetupTest() {
	err := config.InitializeThunderRuntime("", &config.Config{
		OAuth: config.OAuthConfig{
			JWT: config.JWTConfig{},
		},
	})
	assert.NoError(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestGetJWTTokenValidityPeriod() {
	tests := []struct {
		name             string
		configSetup      func()
		expectedValidity int64
	}{
		{
			name: "WithDefaultValue",
			configSetup: func() {
				config.ResetThunderRuntime()
				err := config.InitializeThunderRuntime("", &config.Config{
					OAuth: config.OAuthConfig{
						JWT: config.JWTConfig{
							ValidityPeriod: 0,
						},
					},
				})
				assert.NoError(suite.T(), err)
			},
			expectedValidity: defaultTokenValidity,
		},
		{
			name: "WithCustomValue",
			configSetup: func() {
				config.ResetThunderRuntime()
				err := config.InitializeThunderRuntime("", &config.Config{
					OAuth: config.OAuthConfig{
						JWT: config.JWTConfig{
							ValidityPeriod: 3600,
						},
					},
				})
				assert.NoError(suite.T(), err)
			},
			expectedValidity: 3600,
		},
	}

	for _, tc := range tests {
		suite.T().Run(tc.name, func(t *testing.T) {
			tc.configSetup()

			validity := GetJWTTokenValidityPeriod()
			assert.Equal(t, tc.expectedValidity, validity)
		})
	}
}

func (suite *JWTUtilsTestSuite) TestGetJWTTokenIssuer() {
	tests := []struct {
		name           string
		configSetup    func()
		expectedIssuer string
	}{
		{
			name: "WithDefaultValue",
			configSetup: func() {
				config.ResetThunderRuntime()
				err := config.InitializeThunderRuntime("", &config.Config{
					OAuth: config.OAuthConfig{
						JWT: config.JWTConfig{
							Issuer: "",
						},
					},
				})
				assert.NoError(suite.T(), err)
			},
			expectedIssuer: "thunder",
		},
		{
			name: "WithCustomValue",
			configSetup: func() {
				config.ResetThunderRuntime()
				err := config.InitializeThunderRuntime("", &config.Config{
					OAuth: config.OAuthConfig{
						JWT: config.JWTConfig{
							Issuer: "custom-issuer",
						},
					},
				})
				assert.NoError(suite.T(), err)
			},
			expectedIssuer: "custom-issuer",
		},
	}

	for _, tc := range tests {
		suite.T().Run(tc.name, func(t *testing.T) {
			tc.configSetup()

			issuer := GetJWTTokenIssuer()
			assert.Equal(t, tc.expectedIssuer, issuer)
		})
	}
}

func (suite *JWTUtilsTestSuite) TestDecodeJWT() {
	tests := []struct {
		name            string
		token           string
		expectError     bool
		expectedHeader  map[string]interface{}
		expectedPayload map[string]interface{}
		errorContains   string
	}{
		{
			name: "WithValidToken",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
			expectError:    false,
			expectedHeader: map[string]interface{}{"alg": "HS256", "typ": "JWT"},
			expectedPayload: map[string]interface{}{"sub": "1234567890", "name": "John Doe",
				"iat": float64(1516239022)},
		},
		{
			name:          "WithInvalidTokenFormat",
			token:         "part1.part2",
			expectError:   true,
			errorContains: "invalid JWT format",
		},
		{
			name:        "WithInvalidBase64InHeader",
			token:       "invalid_base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			expectError: true,
		},
		{
			name:        "WithInvalidBase64InPayload",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid_base64.signature",
			expectError: true,
		},
		{
			name:        "WithInvalidJSONInHeader",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVH0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			expectError: true,
		},
		{
			name:        "WithInvalidJSONInPayload",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0c.signature",
			expectError: true,
		},
	}

	for _, tc := range tests {
		suite.T().Run(tc.name, func(t *testing.T) {
			header, payload, err := DecodeJWT(tc.token)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedHeader, header)
				assert.Equal(t, tc.expectedPayload, payload)
			}
		})
	}
}
