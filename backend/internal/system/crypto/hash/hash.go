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

// Package hash provides generic hashing utilities for sensitive data.
package hash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Hash returns a SHA-256 hash of the input byte array.
func Hash(input []byte) string {
	h := sha256.New()
	h.Write(input)
	return hex.EncodeToString(h.Sum(nil))
}

// HashString returns a SHA-256 hash of the input string.
func HashString(input string) string {
	return Hash([]byte(input))
}

// HashStringWithSalt hashes the input string with the given salt and returns the hex-encoded hash.
func HashStringWithSalt(input, salt string) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(input + salt))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// GenerateSalt generates a random salt string.
func GenerateSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}
