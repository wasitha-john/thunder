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

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/asgardeo/thunder/internal/system/config"
)

func TestJWTGeneratorWithKid(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "jwt_test_")
	assert.NoError(t, err)
	defer func() {
		err := os.RemoveAll(tempDir)
		if err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}
	}()

	// Generate test certificate and key
	certFile := filepath.Join(tempDir, "test.crt")
	keyFile := filepath.Join(tempDir, "test.key")
	err = generateTestCertificate(t, certFile, keyFile)
	assert.NoError(t, err)

	// Load the private key for JWT generation
	err = LoadPrivateKey(&config.Config{
		Security: config.SecurityConfig{
			KeyFile: "test.key",
		},
	}, tempDir)
	assert.NoError(t, err)

	// Setup config
	testConfig := &config.Config{
		Security: config.SecurityConfig{
			CertFile: "test.crt",
			KeyFile:  "test.key",
		},
		OAuth: config.OAuthConfig{
			JWT: config.JWTConfig{
				Issuer:         "https://test.issuer.com",
				ValidityPeriod: 3600,
			},
		},
	}

	// Set up Thunder runtime configuration
	err = config.InitializeThunderRuntime(tempDir, testConfig)
	assert.NoError(t, err)

	// Test 1: JWT contains kid
	t.Run("GenerateJWTContainsKid", func(t *testing.T) {
		// Generate JWT
		token, _, err := GenerateJWT("test-subject", "test-audience", 3600, nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Decode JWT header
		header, _, err := DecodeJWT(token)
		assert.NoError(t, err)
		assert.NotNil(t, header)

		// Debug output
		t.Logf("JWT Header: %+v", header)

		// Verify header contains kid
		kid, exists := header["kid"]
		assert.True(t, exists, "JWT header should contain 'kid' field")
		assert.NotEmpty(t, kid, "kid should not be empty")

		// Verify other standard header fields
		assert.Equal(t, "RS256", header["alg"])
		assert.Equal(t, "JWT", header["typ"])
	})

	// Test 2: JWT kid matches JWKS
	t.Run("GenerateJWTKidMatchesJWKS", func(t *testing.T) {
		// Get the kid that would be used by JWKS service
		expectedKid, err := getCertificateKidFromCert(certFile)
		assert.NoError(t, err)

		// Generate JWT
		token, _, err := GenerateJWT("test-subject", "test-audience", 3600, nil)
		assert.NoError(t, err)

		// Decode JWT header
		header, _, err := DecodeJWT(token)
		assert.NoError(t, err)

		// Verify kid matches expected value
		actualKid, exists := header["kid"]
		assert.True(t, exists)
		assert.Equal(t, expectedKid, actualKid, "JWT kid should match certificate SHA-256 thumbprint")
	})

	// Test 3: JWT with custom claims
	t.Run("GenerateJWTWithClaims", func(t *testing.T) {
		customClaims := map[string]string{
			"role":   "admin",
			"tenant": "test-tenant",
		}

		// Generate JWT with custom claims
		token, _, err := GenerateJWT("test-subject", "test-audience", 3600, customClaims)
		assert.NoError(t, err)

		// Decode JWT
		header, payload, err := DecodeJWT(token)
		assert.NoError(t, err)

		// Verify header contains kid
		assert.Contains(t, header, "kid")

		// Verify custom claims are included
		assert.Equal(t, "admin", payload["role"])
		assert.Equal(t, "test-tenant", payload["tenant"])
	})
}

func generateTestCertificate(t *testing.T, certFile, keyFile string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certFile) // #nosec G304 - Test file with controlled path
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := certOut.Close(); closeErr != nil {
			t.Logf("Failed to close cert file: %v", closeErr)
		}
	}()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return err
	}

	// Write private key to file
	keyOut, err := os.Create(keyFile) // #nosec G304 - Test file with controlled path
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := keyOut.Close(); closeErr != nil {
			t.Logf("Failed to close key file: %v", closeErr)
		}
	}()

	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER})
}

// Helper method to get the certificate kid using the same logic as JWKS
func getCertificateKidFromCert(certFile string) (string, error) {
	// Read certificate file
	certData, err := os.ReadFile(certFile) // #nosec G304 - Test file with controlled path
	if err != nil {
		return "", err
	}

	// Parse certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return "", err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	// Calculate SHA-256 thumbprint using the same method as JWKS service
	return calculateCertificateThumbprint(cert), nil
}

// Helper function to calculate certificate thumbprint
func calculateCertificateThumbprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
