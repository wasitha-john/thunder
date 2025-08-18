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

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// CryptoAlgorithm defines the interface that all encryption algorithms must implement.
type CryptoAlgorithm interface {
	Encrypt(key []byte, kid string, plaintext []byte) (string, error)
	Decrypt(key []byte, encodedData string) ([]byte, error)
	Name() Algorithm
}

// AESGCMAlgorithm implements the CryptoAlgorithm interface for AES-GCM.
type AESGCMAlgorithm struct{}

// Encrypt encrypts the given plaintext using AES-GCM and returns a JSON string.
func (a *AESGCMAlgorithm) Encrypt(key []byte, kid string, plaintext []byte) (string, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt and authenticate plaintext, prepend nonce
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	// Create metadata structure
	encData := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:      kid, // Unique identifier for the key
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(encData)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// Decrypt decrypts a JSON string cencrypted using AES-GCM and returns the plaintext.
func (a *AESGCMAlgorithm) Decrypt(key []byte, jsonString string) ([]byte, error) {
	// Deserialize JSON
	var encData EncryptedData
	if err := json.Unmarshal([]byte(jsonString), &encData); err != nil {
		return nil, fmt.Errorf("invalid data format: %w", err)
	}

	// Verify algorithm
	if encData.Algorithm != AESGCM {
		return nil, fmt.Errorf("unsupported algorithm: %s", encData.Algorithm)
	}

	// Decode the payload
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Verify ciphertext length
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and decrypt
	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Name returns the algorithm name.
func (a *AESGCMAlgorithm) Name() Algorithm {
	return AESGCM
}
