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

// Package config provides structures and functions for loading and managing server configurations.
package config

import (
	"os"
	"path/filepath"

	"github.com/asgardeo/thunder/internal/system/log"

	yaml "gopkg.in/yaml.v3"
)

// ServerConfig holds the server configuration details.
type ServerConfig struct {
	Hostname string `yaml:"hostname"`
	Port     int    `yaml:"port"`
}

// SecurityConfig holds the security configuration details.
type SecurityConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// DataSource holds the individual database connection details.
type DataSource struct {
	Type     string `yaml:"type"`
	Hostname string `yaml:"hostname"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
	Path     string `yaml:"path"`
}

// DatabaseConfig holds the different database configuration details.
type DatabaseConfig struct {
	Identity DataSource `yaml:"identity"`
	Runtime  DataSource `yaml:"runtime"`
}

// DefaultUser holds the default user configuration details.
type DefaultUser struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// UserStore holds the user store configuration details.
type UserStore struct {
	DefaultUser DefaultUser `yaml:"default_user"`
}

// Config holds the complete configuration details of the server.
type Config struct {
	Server    ServerConfig   `yaml:"server"`
	Security  SecurityConfig `yaml:"security"`
	Database  DatabaseConfig `yaml:"database"`
	UserStore UserStore      `yaml:"user_store"`
}

// LoadConfig loads the configurations from the specified YAML file.
func LoadConfig(path string) (*Config, error) {
	var cfg Config
	path = filepath.Clean(path)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if ferr := file.Close(); ferr != nil {
			log.GetLogger().Error("Failed to close config file", log.Error(ferr))
		}
	}()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
