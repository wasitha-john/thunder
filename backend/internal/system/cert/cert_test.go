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

package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asgardeo/thunder/internal/system/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const testResourceDir = "../../../tests/resources"

type CertTestSuite struct {
	suite.Suite
	testDir string
}

func TestCertSuite(t *testing.T) {
	suite.Run(t, new(CertTestSuite))
}

func (suite *CertTestSuite) SetupTest() {
	// Create a temporary directory for test certificates
	var err error
	suite.testDir, err = os.MkdirTemp(testResourceDir, "cert-test")
	if err != nil {
		suite.T().Fatalf("Failed to create temp directory: %v", err)
	}
}

func (suite *CertTestSuite) TearDownTest() {
	// Clean up temp directory after tests
	if err := os.RemoveAll(suite.testDir); err != nil {
		suite.T().Errorf("Failed to remove test directory: %v", err)
	}
}

// generateTestCertificate generates a self-signed certificate and private key for testing
func (suite *CertTestSuite) generateTestCertificate() (certPath, keyPath string, err error) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // Valid for 1 day

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"wso2"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// Create certificate file - validate path is within test directory
	certFile := filepath.Join(suite.testDir, "test-cert.pem")
	// Ensure the file path is within the test directory to prevent path traversal
	if !strings.HasPrefix(certFile, suite.testDir) {
		return "", "", fmt.Errorf("invalid certificate file path")
	}

	certOut, err := os.Create(certFile) // #nosec G304
	if err != nil {
		return "", "", err
	}
	defer func() {
		if closeErr := certOut.Close(); closeErr != nil {
			// If we already have an error, don't overwrite it
			if err == nil {
				err = closeErr
			}
		}
	}()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return "", "", err
	}

	// Create key file - validate path is within test directory
	keyFile := filepath.Join(suite.testDir, "test-key.pem")
	// Ensure the file path is within the test directory to prevent path traversal
	if !strings.HasPrefix(keyFile, suite.testDir) {
		return "", "", fmt.Errorf("invalid key file path")
	}

	keyOut, err := os.Create(keyFile) // #nosec G304
	if err != nil {
		return "", "", err
	}
	defer func() {
		if closeErr := keyOut.Close(); closeErr != nil {
			// If we already have an error, don't overwrite it
			if err == nil {
				err = closeErr
			}
		}
	}()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

// createInvalidCertFile creates an invalid certificate file
func (suite *CertTestSuite) createInvalidCertFile() string {
	invalidCertPath := filepath.Join(suite.testDir, "invalid-cert.pem")
	// Ensure the file path is within the test directory to prevent path traversal
	if !strings.HasPrefix(invalidCertPath, suite.testDir) {
		suite.T().Fatalf("Invalid certificate path detected")
		return ""
	}

	// Use 0600 permissions instead of 0644 for better security
	err := os.WriteFile(invalidCertPath, []byte("This is not a valid certificate"), 0600)
	if err != nil {
		suite.T().Fatalf("Failed to create invalid certificate file: %v", err)
	}
	return invalidCertPath
}

func (suite *CertTestSuite) TestGetTLSConfigSuccess() {
	certPath, keyPath, err := suite.generateTestCertificate()
	assert.NoError(suite.T(), err)

	cfg := &config.Config{
		Security: config.SecurityConfig{
			CertFile: filepath.Base(certPath),
			KeyFile:  filepath.Base(keyPath),
		},
	}
	tlsConfig, err := GetTLSConfig(cfg, suite.testDir)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), tlsConfig)
	assert.Equal(suite.T(), 1, len(tlsConfig.Certificates))
}

func (suite *CertTestSuite) TestGetTLSConfigCertFileNotFound() {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			CertFile: "non-existent-cert.pem",
			KeyFile:  "test-key.pem",
		},
	}
	tlsConfig, err := GetTLSConfig(cfg, suite.testDir)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), tlsConfig)
	assert.Contains(suite.T(), err.Error(), "certificate file not found")
}

func (suite *CertTestSuite) TestGetTLSConfigKeyFileNotFound() {
	certPath, _, err := suite.generateTestCertificate()
	assert.NoError(suite.T(), err)

	cfg := &config.Config{
		Security: config.SecurityConfig{
			CertFile: filepath.Base(certPath),
			KeyFile:  "non-existent-key.pem",
		},
	}
	tlsConfig, err := GetTLSConfig(cfg, suite.testDir)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), tlsConfig)
	assert.Contains(suite.T(), err.Error(), "key file not found")
}

func (suite *CertTestSuite) TestGetTLSConfigInvalidCertificate() {
	// Create invalid certificate file
	invalidCertPath := suite.createInvalidCertFile()

	// Create a valid key file
	_, keyPath, err := suite.generateTestCertificate()
	assert.NoError(suite.T(), err)

	cfg := &config.Config{
		Security: config.SecurityConfig{
			CertFile: filepath.Base(invalidCertPath),
			KeyFile:  filepath.Base(keyPath),
		},
	}
	tlsConfig, err := GetTLSConfig(cfg, suite.testDir)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), tlsConfig)
}
