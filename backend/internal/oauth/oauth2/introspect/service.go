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

// Package introspect provides functionality for the OAuth2 token introspection endpoint
package introspect

import (
	"errors"
	"fmt"
	"time"

	"github.com/asgardeo/thunder/internal/oauth/oauth2/constants"
	"github.com/asgardeo/thunder/internal/system/jwt"
	"github.com/asgardeo/thunder/internal/system/log"
)

// TokenIntrospectionServiceInterface defines the interface for OAuth 2.0 token introspection.
type TokenIntrospectionServiceInterface interface {
	IntrospectToken(token, tokenTypeHint string) (*IntrospectResponse, error)
}

// TokenIntrospectionService implements the TokenIntrospectionServiceInterface.
type TokenIntrospectionService struct {
	jwtService jwt.JWTServiceInterface
}

// NewTokenIntrospectionService creates a new TokenIntrospectionService instance.
func NewTokenIntrospectionService(jwtService jwt.JWTServiceInterface) TokenIntrospectionServiceInterface {
	return &TokenIntrospectionService{
		jwtService: jwtService,
	}
}

// IntrospectToken validates and introspects the token. It only returns an error if a server error occurs.
// All other failures are treated as inactive token as defined in the RFC 7662.
func (s *TokenIntrospectionService) IntrospectToken(token, tokenTypeHint string) (*IntrospectResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "TokenIntrospectionService"))

	if token == "" {
		return nil, errors.New("token is required")
	}

	if valid, err := s.verifyTokenSignature(logger, token); err != nil {
		return nil, fmt.Errorf("failed to verify token signature: %w", err)
	} else if !valid {
		return &IntrospectResponse{
			Active: false,
		}, nil
	}

	_, payload, err := jwt.DecodeJWT(token)
	if err != nil {
		logger.Debug("Failed to decode JWT", log.Error(err))
		return &IntrospectResponse{
			Active: false,
		}, nil
	}

	if !s.isValidToken(payload) {
		logger.Debug("Token is not valid based on its claims")
		return &IntrospectResponse{
			Active: false,
		}, nil
	}

	return s.prepareValidResponse(payload), nil
}

// verifyTokenSignature verifies the signature of the JWT token.
func (s *TokenIntrospectionService) verifyTokenSignature(logger *log.Logger, token string) (bool, error) {
	pubKey := s.jwtService.GetPublicKey()
	if pubKey == nil {
		logger.Error("Server public key is not available for JWT verification")
		return false, errors.New("public key is not available")
	}
	if err := s.jwtService.VerifyJWTSignature(token, pubKey); err != nil {
		logger.Debug("Failed to verify token signature", log.Error(err))
		return false, nil
	}
	return true, nil
}

// isValidToken checks if the token is valid based on its claims.
func (s *TokenIntrospectionService) isValidToken(payload map[string]interface{}) bool {
	// Check if the token is expired
	exp, ok := payload["exp"].(float64)
	if !ok {
		return false
	}
	if int64(exp) < time.Now().Unix() {
		return false
	}

	// Check if the token's validity period has started
	nbf, ok := payload["nbf"].(float64)
	if !ok {
		return false
	}
	if int64(nbf) > time.Now().Unix() {
		return false
	}

	// TODO: Add validations for token revocation and validity to be used by the resource server
	//  making the introspection call when the support is implemented.

	return true
}

// prepareValidResponse prepares the response for a valid token introspection.
func (s *TokenIntrospectionService) prepareValidResponse(payload map[string]interface{}) *IntrospectResponse {
	response := &IntrospectResponse{
		Active: true,
		// TODO: Revisit if/when adding support for other token types.
		TokenType: constants.TokenTypeBearer,
	}

	if scope, ok := payload["scope"].(string); ok {
		response.Scope = scope
	}
	if clientID, ok := payload["client_id"].(string); ok {
		response.ClientID = clientID
	}
	if username, ok := payload["username"].(string); ok {
		response.Username = username
	}

	if exp, ok := payload["exp"].(float64); ok {
		response.Exp = int64(exp)
	}
	if iat, ok := payload["iat"].(float64); ok {
		response.Iat = int64(iat)
	}
	if nbf, ok := payload["nbf"].(float64); ok {
		response.Nbf = int64(nbf)
	}

	if sub, ok := payload["sub"].(string); ok {
		response.Sub = sub
	}
	if aud, ok := payload["aud"].(string); ok {
		response.Aud = aud
	}
	if iss, ok := payload["iss"].(string); ok {
		response.Iss = iss
	}
	if jti, ok := payload["jti"].(string); ok {
		response.Jti = jti
	}

	return response
}
