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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	// Reset ThunderRuntime before each test
	config.ResetThunderRuntime()

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
				Issuer:         "https://test.thunder.io",
				ValidityPeriod: 3600, // Default validity period
			},
		},
	}
	err := config.InitializeThunderRuntime("", testConfig)
	assert.NoError(suite.T(), err)

	// Set up CertConfig with test kid
	thunderRuntime := config.GetThunderRuntime()
	thunderRuntime.SetCertConfig(config.CertConfig{
		CertKid: "test-kid",
	})
}

func (suite *JWTServiceTestSuite) TestNewJWTService() {
	service := GetJWTService()
	assert.NotNil(suite.T(), service)
	assert.Implements(suite.T(), (*JWTServiceInterface)(nil), service)
}

func (suite *JWTServiceTestSuite) TestInitScenarios() {
	testCases := []struct {
		name           string
		setupFunc      func() string
		expectSuccess  bool
		expectedErrMsg string
	}{
		{
			name: "Success",
			setupFunc: func() string {
				return suite.testKeyPath // Use the existing valid key path
			},
			expectSuccess:  true,
			expectedErrMsg: "",
		},
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
			expectSuccess:  false,
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
			expectSuccess:  true,
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
			expectSuccess:  false,
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
			expectSuccess:  false,
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
			expectSuccess:  false,
			expectedErrMsg: "",
		},
		{
			name: "KeyFileNotFound",
			setupFunc: func() string {
				return "non_existent_key.pem"
			},
			expectSuccess:  false,
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
			expectSuccess:  false,
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

			// Ensure original config is restored regardless of test outcome
			defer func() {
				thunderRuntime.Config.Security.KeyFile = originalKeyFile
			}()

			thunderRuntime.Config.Security.KeyFile = tc.setupFunc()

			err := jwtService.Init()

			if tc.expectSuccess {
				assert.NoError(t, err)
				assert.NotNil(t, jwtService.privateKey)
			} else {
				assert.Error(t, err)
				if tc.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
				}
			}
		})
	}
}

func (suite *JWTServiceTestSuite) TestGetPublicKey() {
	testCases := []struct {
		name        string
		setupFunc   func() *JWTService
		expectValue bool
		expectedKey *rsa.PublicKey
	}{
		{
			name: "WithValidKey",
			setupFunc: func() *JWTService {
				return suite.jwtService
			},
			expectValue: true,
			expectedKey: &suite.testPrivateKey.PublicKey,
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
			expectedKey: nil,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			jwtService := tc.setupFunc()
			publicKey := jwtService.GetPublicKey()

			if tc.expectValue {
				assert.NotNil(t, publicKey)
				if tc.expectedKey != nil {
					assert.Equal(t, tc.expectedKey, publicKey)
				}
			} else {
				assert.Nil(t, publicKey)
			}
		})
	}
}

func (suite *JWTServiceTestSuite) TestGenerateJWTScenarios() {
	testCases := []struct {
		name               string
		sub                string
		aud                string
		iss                string
		validity           int64
		claims             map[string]interface{}
		setupMock          func() func() // Returns cleanup function
		setupService       func() *JWTService
		expectError        bool
		errorContains      string
		validateSuccess    func(t *testing.T, token string, iat int64)
		useDefaultValidity bool
	}{
		{
			name:     "Success",
			sub:      "test-subject",
			aud:      "test-audience",
			iss:      "test-issuer",
			validity: 3600,
			claims: map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
			},
			setupMock: func() func() {
				return func() {}
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError: false,
			validateSuccess: func(t *testing.T, token string, iat int64) {
				parts := strings.Split(token, ".")
				assert.Len(t, parts, 3)

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

				assert.Equal(t, "test-subject", payload["sub"])
				assert.Equal(t, "test-audience", payload["aud"])
				assert.Equal(t, "test-issuer", payload["iss"])
				assert.NotEmpty(t, payload["jti"])

				// Check claims
				assert.Equal(t, "John Doe", payload["name"])
				assert.Equal(t, "john@example.com", payload["email"])

				assert.True(t, payload["exp"].(float64) > float64(time.Now().Unix()))
				assert.True(t, payload["exp"].(float64) <= float64(time.Now().Unix()+3600+5))
			},
		},
		{
			name:     "DefaultValidity",
			sub:      "test-subject",
			aud:      "test-audience",
			iss:      "test-issuer",
			validity: 0, // Should use default
			claims:   map[string]interface{}{},
			setupMock: func() func() {
				return func() {}
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError:        false,
			useDefaultValidity: true,
		},
		{
			name:     "DefaultIssuer",
			sub:      "test-subject",
			aud:      "test-audience",
			iss:      "", // Should use default
			validity: 3600,
			claims:   map[string]interface{}{},
			setupMock: func() func() {
				return func() {}
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
			iss:       "iss",
			validity:  3600,
			claims:    nil,
			setupMock: func() func() { return func() {} },
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
			name:     "CertificateKidNotFound",
			sub:      "sub",
			aud:      "aud",
			iss:      "iss",
			validity: 3600,
			claims:   nil,
			setupMock: func() func() {
				thunderRuntime := config.GetThunderRuntime()
				originalCertConfig := thunderRuntime.CertConfig
				thunderRuntime.SetCertConfig(config.CertConfig{
					CertKid: "",
				})
				return func() {
					thunderRuntime.SetCertConfig(originalCertConfig)
				}
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError:   true,
			errorContains: "certificate Key ID (kid) not found",
		},
		{
			name:     "CertConfigNotInitialized",
			sub:      "sub",
			aud:      "aud",
			iss:      "iss",
			validity: 3600,
			claims:   nil,
			setupMock: func() func() {
				// Set up ThunderRuntime with uninitialized CertConfig (zero value)
				thunderRuntime := config.GetThunderRuntime()
				originalCertConfig := thunderRuntime.CertConfig
				thunderRuntime.SetCertConfig(config.CertConfig{})
				return func() {
					thunderRuntime.SetCertConfig(originalCertConfig)
				}
			},
			setupService: func() *JWTService {
				return suite.jwtService
			},
			expectError:   true,
			errorContains: "certificate Key ID (kid) not found",
		},
		{
			name:     "WithEmptyClaims",
			sub:      "test-subject",
			aud:      "test-audience",
			iss:      "test-issuer",
			validity: 1800,
			claims:   nil,
			setupMock: func() func() {
				return func() {}
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
			iss:      "iss",
			validity: 3600,
			claims:   nil,
			setupMock: func() func() {
				return func() {}
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
			cleanup := tc.setupMock()
			defer cleanup() // Ensure cleanup runs regardless of test outcome

			jwtService := tc.setupService()

			token, iat, err := jwtService.GenerateJWT(tc.sub, tc.aud, tc.iss, tc.validity, tc.claims)

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

			if tc.validateSuccess != nil {
				tc.validateSuccess(t, token, iat)
			}

			if tc.useDefaultValidity {
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

func (suite *JWTServiceTestSuite) TestVerifyJWTSignature() {
	validToken, _, err := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
	assert.NoError(suite.T(), err)

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create tampered token
	parts := []string{}
	for _, part := range []string{"header", "payload", "signature"} {
		jsonData, _ := json.Marshal(map[string]string{"tampered": part})
		parts = append(parts, base64.RawURLEncoding.EncodeToString(jsonData))
	}
	tamperedToken := parts[0] + "." + parts[1] + "." + parts[2]

	testCases := []struct {
		name        string
		token       string
		publicKey   *rsa.PublicKey
		expectError bool
	}{
		{"ValidToken", validToken, &suite.testPrivateKey.PublicKey, false},
		{"WrongKey", validToken, &wrongKey.PublicKey, true},
		{"InvalidToken", "invalid.token", &suite.testPrivateKey.PublicKey, true},
		{"TamperedToken", tamperedToken, &suite.testPrivateKey.PublicKey, true},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			err := suite.jwtService.VerifyJWTSignature(tc.token, tc.publicKey)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKS() {
	token, _, err := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
	assert.NoError(suite.T(), err)

	testServer := suite.mockJWKSServer()
	defer testServer.Close()

	err = suite.jwtService.VerifyJWTSignatureWithJWKS(token, testServer.URL)
	assert.NoError(suite.T(), err)
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKSInvalidToken() {
	testServer := suite.mockJWKSServer()
	defer testServer.Close()

	testCases := []struct {
		name  string
		token string
	}{
		{"EmptyToken", ""},
		{"MalformedToken", "not.valid.jwt"},
		{"InvalidFormat", "header.payload"},                 // Missing signature part
		{"CorruptedHeader", "aGVhZGVyCg.payload.signature"}, // Non-decodable header
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			err := suite.jwtService.VerifyJWTSignatureWithJWKS(tc.token, testServer.URL)
			assert.Error(t, err)
		})
	}
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKSKeyIDNotFound() {
	testServer := suite.mockJWKSServer()
	defer testServer.Close()

	nonExistentKidJWT := suite.createJWTWithCustomHeader(map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "non-existent-key-id",
	})

	err := suite.jwtService.VerifyJWTSignatureWithJWKS(nonExistentKidJWT, testServer.URL)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "no matching key found")
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKSNoKeyID() {
	testServer := suite.mockJWKSServer()
	defer testServer.Close()

	noKidJWT := suite.createJWTWithCustomHeader(map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		// No kid field
	})

	err := suite.jwtService.VerifyJWTSignatureWithJWKS(noKidJWT, testServer.URL)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "missing 'kid' claim")
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKSHTTPErrors() {
	testCases := []struct {
		name          string
		setupServer   func() *httptest.Server
		setupToken    func() string
		expectedError string
	}{
		{
			name: "HTTPError404",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			setupToken: func() string {
				token, _, _ := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
				return token
			},
			expectedError: "failed to fetch JWKS, status code: 404",
		},
		{
			name: "InvalidJSONResponse",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write([]byte("invalid json")); err != nil {
						suite.T().Errorf("Failed to write response: %v", err)
					}
				}))
			},
			setupToken: func() string {
				token, _, _ := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
				return token
			},
			expectedError: "failed to parse JWKS",
		},
		{
			name: "JWKSWithoutMatchingKid",
			setupServer: func() *httptest.Server {
				// Create JWKS with different kid
				jwks := map[string]interface{}{
					"keys": []interface{}{
						map[string]interface{}{
							"kty": "RSA",
							"kid": "different-kid",
							"n":   "some-n",
							"e":   "AQAB",
						},
					},
				}
				jwksData, _ := json.Marshal(jwks)
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write(jwksData); err != nil {
						suite.T().Errorf("Failed to write response: %v", err)
					}
				}))
			},
			setupToken: func() string {
				token, _, _ := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
				return token
			},
			expectedError: "no matching key found",
		},
		{
			name: "InvalidJWKFormat",
			setupServer: func() *httptest.Server {
				// Create JWKS with invalid JWK (missing n and e)
				jwks := map[string]interface{}{
					"keys": []interface{}{
						map[string]interface{}{
							"kty": "RSA",
							"kid": "test-kid",
							// Missing n and e
						},
					},
				}
				jwksData, _ := json.Marshal(jwks)
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write(jwksData); err != nil {
						suite.T().Errorf("Failed to write response: %v", err)
					}
				}))
			},
			setupToken: func() string {
				token, _, _ := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
				return token
			},
			expectedError: "failed to convert JWK to RSA public key",
		},
		{
			name: "InvalidTokenSignature",
			setupServer: func() *httptest.Server {
				return suite.mockJWKSServer()
			},
			setupToken: func() string {
				// Create a token with wrong signature
				token := suite.createJWTWithCustomHeader(map[string]interface{}{
					"alg": "RS256",
					"typ": "JWT",
					"kid": "test-kid",
				})
				// Modify the last part (signature) to make it invalid
				parts := strings.Split(token, ".")
				parts[2] = "invalid-signature"
				return strings.Join(parts, ".")
			},
			expectedError: "invalid token signature",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			testServer := tc.setupServer()
			defer testServer.Close()

			token := tc.setupToken()

			err := suite.jwtService.VerifyJWTSignatureWithJWKS(token, testServer.URL)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

func (suite *JWTServiceTestSuite) TestVerifyJWTSignatureWithJWKSNetworkError() {
	// Test with invalid URL to trigger network error
	token, _, err := suite.jwtService.GenerateJWT("test-subject", "test-audience", "test-issuer", 3600, nil)
	assert.NoError(suite.T(), err)

	err = suite.jwtService.VerifyJWTSignatureWithJWKS(token, "http://localhost:99999/invalid")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to fetch JWKS")
}

func (suite *JWTServiceTestSuite) TestInitErrorConditions() {
	testCases := []struct {
		name           string
		setupFunc      func() string
		expectedErrMsg string
	}{
		{
			name: "PKCS8NonRSAKey",
			setupFunc: func() string {
				// Create an ECDSA private key (non-RSA)
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				assert.NoError(suite.T(), err)

				pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
				assert.NoError(suite.T(), err)

				pkcs8KeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: pkcs8Bytes,
				})

				tempFile, err := os.CreateTemp("", "ecdsa_key_*.pem")
				assert.NoError(suite.T(), err)
				suite.tempFiles = append(suite.tempFiles, tempFile.Name())

				_, err = tempFile.Write(pkcs8KeyPEM)
				assert.NoError(suite.T(), err)
				err = tempFile.Close()
				assert.NoError(suite.T(), err)

				return tempFile.Name()
			},
			expectedErrMsg: "not an RSA private key",
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
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErrMsg)

			thunderRuntime.Config.Security.KeyFile = originalKeyFile
		})
	}
}

// Helper method to create a JWT with a custom header
func (suite *JWTServiceTestSuite) createJWTWithCustomHeader(header map[string]interface{}) string {
	// Create payload
	payload := map[string]interface{}{
		"sub":  "1234567890",
		"name": "Test User",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	// Encode header and payload
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature input
	signingInput := headerBase64 + "." + payloadBase64

	// Sign
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, suite.testPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		suite.T().Fatalf("Failed to sign JWT: %v", err)
	}

	// Encode signature
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	// Create full JWT
	return headerBase64 + "." + payloadBase64 + "." + signatureBase64
}

// Helper method to create mock JWKS data
func (suite *JWTServiceTestSuite) createMockJWKSData() string {
	n := base64.RawURLEncoding.EncodeToString(suite.testPrivateKey.PublicKey.N.Bytes())

	// Convert exponent to bytes
	eBytes := []byte{1, 0, 1} // 65537 in big-endian
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   n,
		"e":   e,
		"kid": "test-kid",
		"use": "sig",
		"alg": "RS256",
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	jwksData, _ := json.Marshal(jwks)
	return string(jwksData)
}

// Helper method to mock a JWKS server
func (suite *JWTServiceTestSuite) mockJWKSServer() *httptest.Server {
	jwksData := suite.createMockJWKSData()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprintln(w, jwksData); err != nil {
			suite.T().Errorf("Failed to write JWKS response: %v", err)
		}
	}))

	return server
}
