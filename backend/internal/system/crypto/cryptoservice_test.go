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
	"encoding/json"
	"testing"
)

// Mock config for testing.
type MockThunderRuntime struct {
	Config struct {
		Crypto struct {
			Key string
		}
	}
}

func TestCryptoService(t *testing.T) {
	// Generate a random key
	key, err := GenerateRandomKey(DefaultKeySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Logf("Generated random key: %x", key)

	// Create crypto service
	service, err := NewCryptoService(key)
	if err != nil {
		t.Fatalf("Failed to create crypto service: %v", err)
	}

	// Test data
	original := "This is a secret message that needs encryption!"

	// Encrypt
	encrypted, err := service.EncryptString(original)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Encrypted data: %x", encrypted)

	// Decrypt
	decrypted, err := service.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	t.Logf("Decrypted data: %s", decrypted)

	// Verify
	if decrypted != original {
		t.Errorf("Decryption result doesn't match original. Got %q, want %q", decrypted, original)
	}
}

func TestTampering(t *testing.T) {
	// Generate a random key
	key, _ := GenerateRandomKey(DefaultKeySize)
	service, _ := NewCryptoService(key)

	// Encrypt some data
	original := "Protected data"
	encrypted, _ := service.EncryptString(original)

	// Parse the JSON to get the encrypted data structure
	var encData EncryptedData
	err := json.Unmarshal([]byte(encrypted), &encData)
	if err != nil {
		t.Fatalf("Failed to parse encrypted JSON: %v", err)
	}

	// Tamper with the ciphertext field
	cipherBytes := []byte(encData.Ciphertext)
	if len(cipherBytes) > 10 {
		cipherBytes[len(cipherBytes)-5] ^= 0x01 // Flip a bit in the base64 encoded ciphertext
	}
	encData.Ciphertext = string(cipherBytes)

	// Re-encode to JSON
	tamperedJSON, err := json.Marshal(encData)
	if err != nil {
		t.Fatalf("Failed to marshal tampered data: %v", err)
	}

	// Attempt to decrypt tampered data
	out, err := service.DecryptString(string(tamperedJSON))
	if err == nil {
		t.Error("Expected decryption of tampered data to fail, but it succeeded", out)
	}
}

func TestEncryptedObjectFormat(t *testing.T) {
	// Generate a random key
	key, _ := GenerateRandomKey(DefaultKeySize)
	service, _ := NewCryptoService(key)

	// Encrypt some data
	original := "Data to encrypt"
	encrypted, _ := service.EncryptString(original)

	// Parse the JSON to verify structure
	var encData EncryptedData
	err := json.Unmarshal([]byte(encrypted), &encData)
	if err != nil {
		t.Fatalf("Failed to parse encrypted JSON: %v", err)
	}

	// Verify the structure
	if encData.Algorithm != AESGCM {
		t.Errorf("Expected algorithm %s, got %s", AESGCM, encData.Algorithm)
	}
	if encData.Ciphertext == "" {
		t.Error("Ciphertext should not be empty")
	}
	if encData.KeyID != getKeyID(key) {
		t.Error("KeyID should match the expected value")
	}
}

func TestEncryptDecryptCycle(t *testing.T) {
	// Generate a key
	key, _ := GenerateRandomKey(DefaultKeySize)
	service, _ := NewCryptoService(key)

	// Test various data types
	testCases := []string{
		"",                               // Empty string
		"Hello World",                    // Simple text
		"特殊文字列",                          // Unicode characters
		"123456789012345678901234567890", // Long string
		`{"name":"John","age":30}`,       // JSON string
	}

	for _, tc := range testCases {
		encrypted, err := service.EncryptString(tc)
		if err != nil {
			t.Errorf("Failed to encrypt %q: %v", tc, err)
			continue
		}

		decrypted, err := service.DecryptString(encrypted)
		if err != nil {
			t.Errorf("Failed to decrypt %q: %v", tc, err)
			continue
		}

		if decrypted != tc {
			t.Errorf("Decryption result doesn't match original. Got %q, want %q", decrypted, tc)
		}
		t.Logf("Decryption successful. Decrypted data: %q", decrypted)
	}
}

func TestDifferentKeysEncryption(t *testing.T) {
	// Generate two different keys
	key1, _ := GenerateRandomKey(DefaultKeySize)
	key2, _ := GenerateRandomKey(DefaultKeySize)

	service1, _ := NewCryptoService(key1)
	service2, _ := NewCryptoService(key2)

	// Encrypt with first service
	original := "Secret message"
	encrypted, err := service1.EncryptString(original)
	if err != nil {
		t.Fatalf("Encryption with first key failed: %v", err)
	}

	// Try to decrypt with second service (should fail)
	_, err = service2.DecryptString(encrypted)
	if err == nil {
		t.Error("Expected decryption with different key to fail, but it succeeded")
	}
}

func TestNonDefaultKeySize(t *testing.T) {
	// Test various key sizes
	testCases := []int{16, 24} // 128, 192 bits
	// Test data
	original := "This is a secret message that needs encryption!"
	for _, size := range testCases {
		key, _ := GenerateRandomKey(size)
		service, _ := NewCryptoService(key)

		encrypted, err := service.EncryptString(original)
		if err != nil {
			t.Errorf("Failed to encrypt %q: %v", original, err)
			continue
		}

		decrypted, err := service.DecryptString(encrypted)
		if err != nil {
			t.Errorf("Failed to decrypt %q: %v", original, err)
			continue
		}

		if decrypted != original {
			t.Errorf("Decryption result doesn't match original. Got %q, want %q", decrypted, original)
		}
		t.Logf("Decryption successful. Decrypted data: %q", decrypted)
	}
}

func TestWrongKeySize(t *testing.T) {
	// Generate a key of incorrect size
	key, _ := GenerateRandomKey(30)
	service, _ := NewCryptoService(key)
	_, err := service.EncryptString("Test data")
	if err == nil {
		t.Error("Expected error when creating CryptoService with short key, but got none")
	}
}
