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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/tests/mocks/certmock"
)

type JWTServiceTestSuite struct {
	suite.Suite
	mockCertService *certmock.SystemCertificateServiceInterfaceMock
	jwtService      *JWTService
	testPrivateKey  *rsa.PrivateKey
	testKeyPath     string
	tempFiles       []string
}

func TestJWTServiceSuite(t *testing.T) {
	suite.Run(t, new(JWTServiceTestSuite))
}

func (suite *JWTServiceTestSuite) SetupSuite() {
	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)
	suite.testPrivateKey = privateKey

	// Create a temporary private key file
	tempFile, err := os.CreateTemp("", "test_key_*.pem")
	assert.NoError(suite.T(), err)
	suite.testKeyPath = tempFile.Name()

	// Encode the private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Write to file
	_, err = tempFile.Write(privateKeyPEM)
	assert.NoError(suite.T(), err)
	err = tempFile.Close()
	assert.NoError(suite.T(), err)
}

func (suite *JWTServiceTestSuite) TearDownSuite() {
	err := os.Remove(suite.testKeyPath)
	assert.NoError(suite.T(), err)
}

func (suite *JWTServiceTestSuite) AfterTest(_, _ string) {
	// Clean up any temporary files created during tests
	for _, file := range suite.tempFiles {
		err := os.Remove(file)
		if err != nil {
			suite.T().Logf("Failed to remove temp file %s: %v", file, err)
		}
	}
	suite.tempFiles = nil
}

func (suite *JWTServiceTestSuite) SetupTest() {
	suite.mockCertService = certmock.NewSystemCertificateServiceInterfaceMock(suite.T())

	suite.jwtService = &JWTService{
		privateKey:               suite.testPrivateKey,
		SystemCertificateService: suite.mockCertService,
	}

	testConfig := &config.Config{
		Security: config.SecurityConfig{
			KeyFile: suite.testKeyPath,
		},
		OAuth: config.OAuthConfig{
			JWT: config.JWTConfig{
				Issuer: "https://test.thunder.io",
			},
		},
	}
	err := config.InitializeThunderRuntime("", testConfig)
	assert.NoError(suite.T(), err)
}

func (suite *JWTServiceTestSuite) TestNewJWTService() {
	service := GetJWTService()
	assert.NotNil(suite.T(), service)
	assert.Implements(suite.T(), (*JWTServiceInterface)(nil), service)
}

func (suite *JWTServiceTestSuite) TestInit_Success() {
	jwtService := &JWTService{
		SystemCertificateService: suite.mockCertService,
	}
	err := jwtService.Init()

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), jwtService.privateKey)
}

func (suite *JWTServiceTestSuite) TestInitScenarios() {
	testCases := []struct {
		name           string
		setupFunc      func() string
		expectedErrMsg string
	}{
		{
			name: "ReadFileError",
			setupFunc: func() string {
				tempFile, err := os.CreateTemp("", "no_read_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				err = tempFile.Chmod(0000) // Remove all permissions
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "",
		},
		{
			name: "PKCS8Key",
			setupFunc: func() string {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				assert.NoError(suite.T(), err)

				pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
				assert.NoError(suite.T(), err)

				pkcs8KeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY", // This is the PKCS8 standard header
					Bytes: pkcs8Bytes,
				})

				tempFile, err := os.CreateTemp("", "pkcs8_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.Write(pkcs8KeyPEM)
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "",
		},
		{
			name: "InvalidPKCS8Key",
			setupFunc: func() string {
				invalidPKCS8PEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: []byte{0x01, 0x02, 0x03, 0x04}, // Invalid PKCS8 format
				})

				tempFile, err := os.CreateTemp("", "invalid_pkcs8_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.Write(invalidPKCS8PEM)
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "",
		},
		{
			name: "InvalidKeyType",
			setupFunc: func() string {
				unsupportedKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "UNSUPPORTED KEY TYPE",
					Bytes: []byte{0x01, 0x02, 0x03, 0x04},
				})

				tempFile, err := os.CreateTemp("", "unsupported_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.Write(unsupportedKeyPEM)
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "unsupported private key type",
		},
		{
			name: "InvalidPKCS1Key",
			setupFunc: func() string {
				invalidPKCS1PEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: []byte{0x01, 0x02, 0x03, 0x04}, // Invalid PKCS1 format
				})

				tempFile, err := os.CreateTemp("", "invalid_pkcs1_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.Write(invalidPKCS1PEM)
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "",
		},
		{
			name: "KeyFileNotFound",
			setupFunc: func() string {
				return "non_existent_key.pem"
			},
			expectedErrMsg: "key file not found",
		},
		{
			name: "InvalidPEMBlock",
			setupFunc: func() string {
				tempFile, err := os.CreateTemp("", "invalid_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.WriteString("This is not a valid PEM block")
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "failed to decode PEM block",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			jwtService := &JWTService{
				SystemCertificateService: suite.mockCertService,
			}

			thunderRuntime := config.GetThunderRuntime()
			originalKeyFile := thunderRuntime.Config.Security.KeyFile
			thunderRuntime.Config.Security.KeyFile = tc.setupFunc()

			err := jwtService.Init()

			if tc.expectedErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else if tc.name == "PKCS8Key" {
				assert.NoError(t, err)
				assert.NotNil(t, jwtService.privateKey)
			} else if tc.name == "ReadFileError" || tc.name == "InvalidPKCS8Key" || tc.name == "InvalidPKCS1Key" {
				assert.Error(t, err)
			}

			thunderRuntime.Config.Security.KeyFile = originalKeyFile
		})
	}
}

func (suite *JWTServiceTestSuite) TestGetPublicKey() {
	testCases := []struct {
		name        string
		setupFunc   func() *JWTService
		expectValue bool
	}{
		{
			name: "WithValidKey",
			setupFunc: func() *JWTService {
				return suite.jwtService
			},
			expectValue: true,
		},
		{
			name: "WithNilKey",
			setupFunc: func() *JWTService {
				return &JWTService{
					privateKey:               nil,
					SystemCertificateService: suite.mockCertService,
				}
			},
			expectValue: false,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			jwtService := tc.setupFunc()
			publicKey := jwtService.GetPublicKey()

			if tc.expectValue {
				assert.NotNil(t, publicKey)
				if tc.name == "WithValidKey" {
					assert.Equal(t, &suite.testPrivateKey.PublicKey, publicKey)
				}
			} else {
				assert.Nil(t, publicKey)
			}
		})
	}
}

func (suite *JWTServiceTestSuite) TestGenerateJWTScenarios() {
	testCases := []struct {
		name          string
		sub           string
		aud           string
		validity      int64
		claims        map[string]string
		setupMock     func()
		setupService  func() *JWTService
		expectError   bool
		errorContains string
	}{
		{
			name:     "Success",
			sub:      "test-subject",
			aud:      "test-audience",
			validity: 3600,
			claims: map[string]string{
				"name":  "John Doe",
				"email": "john@example.com",
			},
			setupMock: func() {
				suite.mockCertService.On("GetCertificateKid").Return("test-kid", nil).Once()
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError: false,
		},
		{
			name:     "DefaultValidity",
			sub:      "test-subject",
			aud:      "test-audience",
			validity: 0, // Should use default
			claims:   map[string]string{},
			setupMock: func() {
				suite.mockCertService.On("GetCertificateKid").Return("test-kid", nil).Once()
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError: false,
		},
		{
			name:      "NilPrivateKey",
			sub:       "sub",
			aud:       "aud",
			validity:  3600,
			claims:    nil,
			setupMock: func() {},
			setupService: func() *JWTService {
				return &JWTService{
					privateKey:               nil,
					SystemCertificateService: suite.mockCertService,
				}
			},
			expectError:   true,
			errorContains: "private key not loaded",
		},
		{
			name:     "GetCertificateKidError",
			sub:      "sub",
			aud:      "aud",
			validity: 3600,
			claims:   nil,
			setupMock: func() {
				suite.mockCertService.On("GetCertificateKid").Return("", errors.New("kid error")).Once()
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError:   true,
			errorContains: "kid error",
		},
		{
			name:     "WithEmptyClaims",
			sub:      "test-subject",
			aud:      "test-audience",
			validity: 1800,
			claims:   nil,
			setupMock: func() {
				suite.mockCertService.On("GetCertificateKid").Return("test-kid", nil).Once()
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError: false,
		},
		{
			name:     "SigningError",
			sub:      "sub",
			aud:      "aud",
			validity: 3600,
			claims:   nil,
			setupMock: func() {
				suite.mockCertService.On("GetCertificateKid").Return("test-kid", nil).Once()
			},
			setupService: func() *JWTService {
				return &JWTService{
					privateKey:               &rsa.PrivateKey{}, // Invalid private key
					SystemCertificateService: suite.mockCertService,
				}
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			tc.setupMock()
			jwtService := tc.setupService()

			token, iat, err := jwtService.GenerateJWT(tc.sub, tc.aud, tc.validity, tc.claims)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Empty(t, token)
				assert.Equal(t, int64(0), iat)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.True(t, iat > 0)

			parts := strings.Split(token, ".")
			assert.Len(t, parts, 3)

			// Only for success case, perform more detailed validation
			if tc.name == "Success" {
				headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
				assert.NoError(t, err)

				var header map[string]string
				err = json.Unmarshal(headerBytes, &header)
				assert.NoError(t, err)

				assert.Equal(t, "RS256", header["alg"])
				assert.Equal(t, "JWT", header["typ"])
				assert.Equal(t, "test-kid", header["kid"])

				payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
				assert.NoError(t, err)

				var payload map[string]interface{}
				err = json.Unmarshal(payloadBytes, &payload)
				assert.NoError(t, err)

				assert.Equal(t, tc.sub, payload["sub"])
				assert.Equal(t, tc.aud, payload["aud"])
				assert.Equal(t, "https://test.thunder.io", payload["iss"])
				assert.NotEmpty(t, payload["jti"])

				if tc.claims != nil {
					for k, v := range tc.claims {
						assert.Equal(t, v, payload[k])
					}
				}

				assert.True(t, payload["exp"].(float64) > float64(time.Now().Unix()))
				assert.True(t, payload["exp"].(float64) <= float64(time.Now().Unix()+tc.validity+5))
			}

			// For DefaultValidity case, check if the default expiry is applied
			if tc.name == "DefaultValidity" {
				payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
				assert.NoError(t, err)

				var payload map[string]interface{}
				err = json.Unmarshal(payloadBytes, &payload)
				assert.NoError(t, err)

				now := time.Now().Unix()
				assert.True(t, payload["exp"].(float64) >= float64(now+3600-5))
				assert.True(t, payload["exp"].(float64) <= float64(now+3600+5))
			}
		})
	}
}
