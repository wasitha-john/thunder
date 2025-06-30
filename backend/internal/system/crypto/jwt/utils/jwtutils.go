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

// Package utils provides utility functions for working with JWT tokens.
package utils

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	httpservice "github.com/asgardeo/thunder/internal/system/http"
)

// ParseJWTClaims parses a JWT token and extracts its claims.
// This function doesn't verify the token signature, so it should only be used when the token
// has been obtained from a trusted source or after signature verification.
func ParseJWTClaims(jwtToken string) (map[string]interface{}, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	return claims, nil
}

// VerifyJWTSignature verifies the signature of a JWT token using the provided public key.
func VerifyJWTSignature(jwtToken string, jwtPublicKey *rsa.PublicKey) error {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT token format")
	}

	// Decode the signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	// Create the signing input
	signingInput := parts[0] + "." + parts[1]

	// Hash the signing input
	hashed := sha256.Sum256([]byte(signingInput))

	// Verify the signature
	return rsa.VerifyPKCS1v15(jwtPublicKey, crypto.SHA256, hashed[:], signature)
}

// ParseJWTHeader extracts the header from a JWT token.
func ParseJWTHeader(jwtToken string) (map[string]interface{}, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token format")
	}

	// Decode the header (first part)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %w", err)
	}

	return header, nil
}

// JWKToRSAPublicKey converts a JWK (JSON Web Key) to an RSA Public Key.
func JWKToRSAPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	// Extract modulus (n) and exponent (e) from JWK
	n, ok := jwk["n"].(string)
	if !ok {
		return nil, errors.New("invalid JWK format, missing 'n' parameter")
	}

	e, ok := jwk["e"].(string)
	if !ok {
		return nil, errors.New("invalid JWK format, missing 'e' parameter")
	}

	// Decode modulus and exponent from Base64URL
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var eInt int
	for i := 0; i < len(eBytes); i++ {
		eInt = eInt<<8 + int(eBytes[i])
	}

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return pubKey, nil
}

// VerifyJWTSignatureWithJWKS verifies the signature of a JWT token using a JWK Set (JWKS) endpoint.
func VerifyJWTSignatureWithJWKS(jwtToken string, jwksURL string) error {
	// Get the key ID from the JWT header
	header, err := ParseJWTHeader(jwtToken)
	if err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return fmt.Errorf("JWT header missing 'kid' claim")
	}

	// Fetch the JWK Set from the JWKS endpoint
	client := httpservice.NewHTTPClientWithTimeout(10 * time.Second)
	resp, err := client.Get(jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Find the key with matching kid
	var jwk map[string]interface{}
	for _, key := range jwks.Keys {
		if keyID, ok := key["kid"].(string); ok && keyID == kid {
			jwk = key
			break
		}
	}
	if jwk == nil {
		return fmt.Errorf("no matching key found in JWKS")
	}

	// Convert JWK to RSA public key
	pubKey, err := JWKToRSAPublicKey(jwk)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to RSA public key: %w", err)
	}

	// Verify JWT signature
	if err := VerifyJWTSignature(jwtToken, pubKey); err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	return nil
}
