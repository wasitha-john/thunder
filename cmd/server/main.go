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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/asgardeo/thunder/internal/cert"
	"github.com/asgardeo/thunder/internal/identity/jwt"
	"github.com/asgardeo/thunder/internal/managers"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"

	"go.uber.org/zap"
)

func main() {

	// Initialize the logger.
	if err := log.InitLogger(); err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer log.Sync()
	logger := log.GetLogger()

	// Get the Thunder home directory.
	thunderHome := getThunderHome(logger)

	// Initialize the server.
	cfg := initThunderConfigurations(logger, thunderHome)
	if cfg == nil {
		logger.Fatal("Failed to initialize configurations")
	}

	// Initialize the multiplexer and register services.
	mux := initMultiPlexer(logger, cfg)
	if mux == nil {
		logger.Fatal("Failed to initialize multiplexer")
	}

	startServer(logger, cfg, mux, thunderHome)
}

// getThunderHome retrieves and return the Thunder home directory.
func getThunderHome(logger *zap.Logger) string {

	// Parse project directory from command line arguments.
	projectHome := ""
	projectHomeFlag := flag.String("thunderHome", "", "Path to Asgardeo Thunder home directory")
	flag.Parse()

	if *projectHomeFlag != "" {
		logger.Info("Using thunderHome from command line argument", zap.String("thunderHome", *projectHomeFlag))
		projectHome = *projectHomeFlag
	} else {
		// If no command line argument is provided, use the current working directory.
		dir, dirErr := os.Getwd()
		if dirErr != nil {
			logger.Fatal("Failed to get current working directory", zap.Error(dirErr))
		}
		projectHome = dir
	}

	return projectHome
}

// initThunderConfigurations initializes the Thunder configurations.
func initThunderConfigurations(logger *zap.Logger, thunderHome string) *config.Config {

	// Load the configurations.
	configFilePath := path.Join(thunderHome, "repository/conf/deployment.yaml")
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		logger.Fatal("Failed to load configurations", zap.Error(err))
	}

	// Load the server's private key for signing JWTs.
	if err := jwt.LoadPrivateKey(cfg, thunderHome); err != nil {
		logger.Fatal("Failed to load private key", zap.Error(err))
	}

	return cfg
}

// initMultiPlexer initializes the HTTP multiplexer and registers the services.
func initMultiPlexer(logger *zap.Logger, cfg *config.Config) *http.ServeMux {

	mux := http.NewServeMux()
	serviceManager := managers.NewServiceManager(mux, cfg)

	// Register the services.
	err := serviceManager.RegisterServices()
	if err != nil {
		logger.Fatal("Failed to register the services", zap.Error(err))
	}

	return mux
}

// startServer starts the HTTP server with the given configurations and multiplexer.
func startServer(logger *zap.Logger, cfg *config.Config, mux *http.ServeMux, thunderHome string) {

	// Get TLS configuration from the certificate and key files.
	tlsConfig, err := cert.GetTLSConfig(cfg, thunderHome)
	if err != nil {
		logger.Fatal("Failed to load TLS configuration", zap.Error(err))
	}

	// Build the server address using hostname and port from the configurations.
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Hostname, cfg.Server.Port)

	server := &http.Server{
		Addr:      serverAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	logger.Info("Starting Asgardeo Thunder...", zap.String("address", serverAddr))

	if err := server.ListenAndServeTLS("", ""); err != nil {
		logger.Fatal("Server failed to start", zap.Error(err))
	}
}
