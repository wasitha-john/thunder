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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type JWTUtilsTestSuite struct {
	suite.Suite
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	validJWT      string
	invalidJWT    string
	testServer    *httptest.Server
}

func TestJWTUtilsSuite(t *testing.T) {
	suite.Run(t, new(JWTUtilsTestSuite))
}

func (suite *JWTUtilsTestSuite) SetupTest() {
	// Generate RSA key pair for testing
	var err error
	suite.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		suite.T().Fatalf("Failed to generate RSA key: %v", err)
	}
	suite.rsaPublicKey = &suite.rsaPrivateKey.PublicKey

	// Create a valid JWT token
	suite.validJWT = suite.createValidJWT()

	// Create an invalid JWT token
	suite.invalidJWT = "invalid.jwt.token"

	// Create a mock HTTP server for JWKS
	suite.testServer = suite.mockJWKSServer()
}

func (suite *JWTUtilsTestSuite) TearDownTest() {
	// Clean up the test server
	if suite.testServer != nil {
		suite.testServer.Close()
	}
}

// Helper method to create a valid JWT token for testing
func (suite *JWTUtilsTestSuite) createValidJWT() string {
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key-id",
	}

	payload := map[string]interface{}{
		"sub":  "1234567890",
		"name": "Test User",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerBase64 + "." + payloadBase64

	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, suite.rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		suite.T().Fatalf("Failed to sign JWT: %v", err)
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return headerBase64 + "." + payloadBase64 + "." + signatureBase64
}

func (suite *JWTUtilsTestSuite) TestParseJWTClaims() {
	claims, err := ParseJWTClaims(suite.validJWT)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims)
	assert.Equal(suite.T(), "Test User", claims["name"])
	assert.Equal(suite.T(), "1234567890", claims["sub"])
}

func (suite *JWTUtilsTestSuite) TestParseJWTClaimsInvalid() {
	testCases := []struct {
		name  string
		token string
	}{
		{"InvalidFormat", "invalid.format"},
		{"EmptyToken", ""},
		{"MalformedPayload", "header.notbase64encoded.signature"},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			claims, err := ParseJWTClaims(tc.token)

			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignature() {
	err := VerifyJWTSignature(suite.validJWT, suite.rsaPublicKey)
	assert.NoError(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureWrongKey() {
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := VerifyJWTSignature(suite.validJWT, &wrongKey.PublicKey)
	assert.Error(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureInvalidToken() {
	err := VerifyJWTSignature("invalid.token", suite.rsaPublicKey)
	assert.Error(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureTamperedToken() {
	parts := []string{}
	for _, part := range []string{"header", "payload", "signature"} {
		jsonData, _ := json.Marshal(map[string]string{"tampered": part})
		parts = append(parts, base64.RawURLEncoding.EncodeToString(jsonData))
	}
	tamperedToken := parts[0] + "." + parts[1] + "." + parts[2]

	err := VerifyJWTSignature(tamperedToken, suite.rsaPublicKey)
	assert.Error(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestParseJWTHeader() {
	header, err := ParseJWTHeader(suite.validJWT)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), header)
	assert.Equal(suite.T(), "RS256", header["alg"])
	assert.Equal(suite.T(), "JWT", header["typ"])
	assert.Equal(suite.T(), "test-key-id", header["kid"])
}

func (suite *JWTUtilsTestSuite) TestParseJWTHeaderInvalid() {
	header, err := ParseJWTHeader(suite.invalidJWT)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), header)
}

func (suite *JWTUtilsTestSuite) TestJWKToRSAPublicKey() {
	// Create a JWK from the RSA public key
	n := base64.RawURLEncoding.EncodeToString(suite.rsaPublicKey.N.Bytes())

	// Convert exponent to bytes
	eBytes := []byte{1, 0, 1} // 65537 in big-endian
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   n,
		"e":   e,
		"kid": "test-key-id",
	}

	pubKey, err := JWKToRSAPublicKey(jwk)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), pubKey)
	assert.Equal(suite.T(), suite.rsaPublicKey.E, pubKey.E)
}

func (suite *JWTUtilsTestSuite) TestJWKToRSAPublicKeyInvalid() {
	// Create a JWK from the RSA public key
	n := base64.RawURLEncoding.EncodeToString(suite.rsaPublicKey.N.Bytes())

	// Convert exponent to bytes
	eBytes := []byte{1, 0, 1} // 65537 in big-endian
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	// Test with missing parameters
	invalidTestCases := []struct {
		name string
		jwk  map[string]interface{}
	}{
		{"MissingN", map[string]interface{}{"e": e}},
		{"MissingE", map[string]interface{}{"n": n}},
		{"InvalidN", map[string]interface{}{"n": "invalid@base64!", "e": e}},
		{"InvalidE", map[string]interface{}{"n": n, "e": "invalid@base64!"}},
	}

	for _, tc := range invalidTestCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			pubKey, err := JWKToRSAPublicKey(tc.jwk)

			assert.Error(t, err)
			assert.Nil(t, pubKey)
		})
	}
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureWithJWKS() {
	err := VerifyJWTSignatureWithJWKS(suite.validJWT, suite.testServer.URL)
	assert.NoError(suite.T(), err)
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureWithJWKSInvalidToken() {
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
			err := VerifyJWTSignatureWithJWKS(tc.token, suite.testServer.URL)
			assert.Error(t, err)
		})
	}
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureWithJWKSKeyIDNotFound() {
	nonExistentKidJWT := suite.createJWTWithCustomHeader(map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "non-existent-key-id",
	})

	err := VerifyJWTSignatureWithJWKS(nonExistentKidJWT, suite.testServer.URL)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "no matching key found")
}

func (suite *JWTUtilsTestSuite) TestVerifyJWTSignatureWithJWKSNoKeyID() {
	noKidJWT := suite.createJWTWithCustomHeader(map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		// No kid field
	})

	err := VerifyJWTSignatureWithJWKS(noKidJWT, suite.testServer.URL)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "missing 'kid' claim")
}

// Helper method to create a JWT with a custom header
func (suite *JWTUtilsTestSuite) createJWTWithCustomHeader(header map[string]interface{}) string {
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, suite.rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		suite.T().Fatalf("Failed to sign JWT: %v", err)
	}

	// Encode signature
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	// Create full JWT
	return headerBase64 + "." + payloadBase64 + "." + signatureBase64
}

// Helper method to create mock JWKS data
func (suite *JWTUtilsTestSuite) createMockJWKSData() string {
	n := base64.RawURLEncoding.EncodeToString(suite.rsaPublicKey.N.Bytes())

	// Convert exponent to bytes
	eBytes := []byte{1, 0, 1} // 65537 in big-endian
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   n,
		"e":   e,
		"kid": "test-key-id",
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
func (suite *JWTUtilsTestSuite) mockJWKSServer() *httptest.Server {
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
