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

package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const testResourceDir = "../../../tests/resources"

type ConfigTestSuite struct {
	suite.Suite
}

func TestConfigSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

func (suite *ConfigTestSuite) getFilePath(filename string) string {
	return filepath.Join(testResourceDir, filename)
}

func (suite *ConfigTestSuite) TestLoadConfigValid() {
	configPath := suite.getFilePath("deployment.yaml")
	config, err := LoadConfig(configPath)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), config)

	// Verify server config
	assert.Equal(suite.T(), "localhost", config.Server.Hostname)
	assert.Equal(suite.T(), 8080, config.Server.Port)

	// Verify gate client config
	assert.Equal(suite.T(), "localhost", config.GateClient.Hostname)
	assert.Equal(suite.T(), 9090, config.GateClient.Port)
	assert.Equal(suite.T(), "https", config.GateClient.Scheme)
	assert.Equal(suite.T(), "/login", config.GateClient.LoginPath)
	assert.Equal(suite.T(), "/error", config.GateClient.ErrorPath)

	// Verify security config
	assert.Equal(suite.T(), "/path/to/cert.pem", config.Security.CertFile)
	assert.Equal(suite.T(), "/path/to/key.pem", config.Security.KeyFile)

	// Verify database config
	assert.Equal(suite.T(), "postgres", config.Database.Identity.Type)
	assert.Equal(suite.T(), "postgres", config.Database.Identity.Username)
	assert.Equal(suite.T(), "sqlite", config.Database.Runtime.Type)
	assert.Equal(suite.T(), "/data/runtime.db", config.Database.Runtime.Path)

	// Verify OAuth config
	assert.Equal(suite.T(), "thunder", config.OAuth.JWT.Issuer)
	assert.Equal(suite.T(), int64(3600), config.OAuth.JWT.ValidityPeriod)

	// Verify flow config
	assert.Equal(suite.T(), "repository/resources/graphs/", config.Flow.GraphDirectory)
	assert.Equal(suite.T(), "auth_flow_config_basic", config.Flow.Authn.DefaultFlow)
}

func (suite *ConfigTestSuite) TestLoadConfigFileNotFound() {
	configPath := suite.getFilePath("non_existent_config.yaml")
	config, err := LoadConfig(configPath)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), config)
	assert.Contains(suite.T(), err.Error(), "no such file or directory")
}

func (suite *ConfigTestSuite) TestLoadConfigInvalidYAML() {
	configPath := suite.getFilePath("invalid_deployment.yaml")

	config, err := LoadConfig(configPath)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), config)
}
