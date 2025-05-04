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
	"crypto/tls"
	"errors"
	"os"
	"path"

	"github.com/asgardeo/thunder/internal/system/config"
)

// GetTLSConfig loads the TLS configuration from the certificate and key files.
func GetTLSConfig(cfg *config.Config, currentDirectory string) (*tls.Config, error) {

	certFilePath := path.Join(currentDirectory, cfg.Security.CertFile)
	keyFilePath := path.Join(currentDirectory, cfg.Security.KeyFile)

	// Check if the certificate and key files exist.
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		return nil, errors.New("certificate file not found at " + certFilePath)
	}
	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		return nil, errors.New("key file not found at " + keyFilePath)
	}

	// Load the certificate and key.
	cert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}

	// Return the TLS configuration.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
