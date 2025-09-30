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

package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// PKCE validation errors
var (
	ErrInvalidCodeVerifier    = errors.New("invalid code verifier")
	ErrInvalidCodeChallenge   = errors.New("invalid code challenge")
	ErrInvalidChallengeMethod = errors.New("invalid code challenge method")
	ErrPKCEValidationFailed   = errors.New("PKCE validation failed")
)

// ValidatePKCE validates the PKCE code verifier against the stored code challenge.
func ValidatePKCE(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	if codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}

	if err := validatePKCEParameters(codeChallenge, codeChallengeMethod, codeVerifier); err != nil {
		return err
	}

	switch codeChallengeMethod {
	case "plain":
		return validatePlainChallenge(codeChallenge, codeVerifier)
	case "S256":
		return validateS256Challenge(codeChallenge, codeVerifier)
	default:
		return ErrInvalidChallengeMethod
	}
}

// validatePKCEParameters validates the basic format of PKCE parameters.
func validatePKCEParameters(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	if codeVerifier == "" {
		return ErrInvalidCodeVerifier
	}
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return ErrInvalidCodeVerifier
	}
	if !isValidCodeVerifier(codeVerifier) {
		return ErrInvalidCodeVerifier
	}

	if codeChallenge == "" {
		return ErrInvalidCodeChallenge
	}

	if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		return ErrInvalidChallengeMethod
	}

	return nil
}

// validatePlainChallenge validates a plain code challenge.
func validatePlainChallenge(codeChallenge, codeVerifier string) error {
	if codeChallenge != codeVerifier {
		return ErrPKCEValidationFailed
	}
	return nil
}

// validateS256Challenge validates an S256 code challenge.
func validateS256Challenge(codeChallenge, codeVerifier string) error {
	hash := sha256.Sum256([]byte(codeVerifier))

	expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	if codeChallenge != expectedChallenge {
		return ErrPKCEValidationFailed
	}
	return nil
}

// isValidCodeVerifier checks if the code verifier contains only valid characters.
func isValidCodeVerifier(codeVerifier string) bool {
	for i := 0; i < len(codeVerifier); i++ {
		c := codeVerifier[i]
		if !((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~') {
			return false
		}
	}
	return true
}

// GenerateCodeChallenge generates a code challenge from a code verifier using the specified method.
func GenerateCodeChallenge(codeVerifier, method string) (string, error) {
	if codeVerifier == "" {
		return "", ErrInvalidCodeVerifier
	}
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return "", ErrInvalidCodeVerifier
	}
	if !isValidCodeVerifier(codeVerifier) {
		return "", ErrInvalidCodeVerifier
	}
	
	if method != "plain" && method != "S256" {
		return "", ErrInvalidChallengeMethod
	}

	switch method {
	case "plain":
		return codeVerifier, nil
	case "S256":
		hash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
	default:
		return "", ErrInvalidChallengeMethod
	}
}

// ValidateCodeChallenge validates the format of a code challenge according to RFC 7636.
func ValidateCodeChallenge(codeChallenge, codeChallengeMethod string) error {
	if codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}

	if codeChallengeMethod == "plain" {
		if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
			return ErrInvalidCodeChallenge
		}
		if !isValidCodeVerifier(codeChallenge) {
			return ErrInvalidCodeChallenge
		}
		return nil
	}

	if codeChallengeMethod == "S256" {
		if len(codeChallenge) != 43 {
			return ErrInvalidCodeChallenge
		}
		// Validate base64url characters
		for i := 0; i < len(codeChallenge); i++ {
			c := codeChallenge[i]
			if !((c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '_') {
				return ErrInvalidCodeChallenge
			}
		}
		return nil
	}

	return ErrInvalidCodeChallenge
}
