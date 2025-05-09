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
	"crypto/tls"
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
)

func main() {

	// Initialize the logger.
	logger := log.GetLogger()

	// Get the Thunder home directory.
	thunderHome := getThunderHome(logger)

	// Initialize the server.
	cfg := initThunderConfigurations(logger, thunderHome)
	if cfg == nil {
		logger.Fatal("Failed to initialize configurations")
	}

	// Initialize the multiplexer and register services.
	mux := initMultiplexer(logger, thunderHome)
	if mux == nil {
		logger.Fatal("Failed to initialize multiplexer")
	}

	startServer(logger, cfg, mux, thunderHome)
}

// getThunderHome retrieves and return the Thunder home directory.
func getThunderHome(logger *log.Logger) string {

	// Parse project directory from command line arguments.
	projectHome := ""
	projectHomeFlag := flag.String("thunderHome", "", "Path to Thunder home directory")
	flag.Parse()

	if *projectHomeFlag != "" {
		logger.Info("Using thunderHome from command line argument", log.String("thunderHome", *projectHomeFlag))
		projectHome = *projectHomeFlag
	} else {
		// If no command line argument is provided, use the current working directory.
		dir, dirErr := os.Getwd()
		if dirErr != nil {
			logger.Fatal("Failed to get current working directory", log.Error(dirErr))
		}
		projectHome = dir
	}

	return projectHome
}

// initThunderConfigurations initializes the Thunder configurations.
func initThunderConfigurations(logger *log.Logger, thunderHome string) *config.Config {

	// Load the configurations.
	configFilePath := path.Join(thunderHome, "repository/conf/deployment.yaml")
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		logger.Fatal("Failed to load configurations", log.Error(err))
	}

	// Load the server's private key for signing JWTs.
	if err := jwt.LoadPrivateKey(cfg, thunderHome); err != nil {
		logger.Fatal("Failed to load private key", log.Error(err))
	}

	// Initialize runtime configurations.
	if err := config.InitializeThunderRuntime(thunderHome, cfg); err != nil {
		logger.Fatal("Failed to initialize thunder runtime", log.Error(err))
	}

	return cfg
}

// initMultiplexer initializes the HTTP multiplexer and registers the services.
func initMultiplexer(logger *log.Logger, thunderHome string) *http.ServeMux {

	mux := http.NewServeMux()
	serviceManager := managers.NewServiceManager(mux)

	// Register the services.
	err := serviceManager.RegisterServices()
	if err != nil {
		logger.Fatal("Failed to register the services", log.Error(err))
	}

	// Register static frontend assets.
	registerFrontendAssets(logger, mux, thunderHome)

	return mux
}

// startServer starts the HTTP server with the given configurations and multiplexer.
func startServer(logger *log.Logger, cfg *config.Config, mux *http.ServeMux, thunderHome string) {

	// Get TLS configuration from the certificate and key files.
	tlsConfig, err := cert.GetTLSConfig(cfg, thunderHome)
	if err != nil {
		logger.Fatal("Failed to load TLS configuration", log.Error(err))
	}

	// Build the server address using hostname and port from the configurations.
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Hostname, cfg.Server.Port)

	ln, err := tls.Listen("tcp", serverAddr, tlsConfig) // listener bound to port
	if err != nil {
		logger.Fatal("Failed to start TLS listener", log.Error(err))
	}

	logger.Info("WSO2 Thunder started...", log.String("address", serverAddr))

	server := &http.Server{Handler: mux}

	if err := server.Serve(ln); err != nil {
		logger.Fatal("Failed to serve requests", log.Error(err))
	}
}

// registerFrontendAssets registers the frontend React app's static file handler.
func registerFrontendAssets(logger *log.Logger, mux *http.ServeMux, thunderHome string) {

	frontendPath := path.Join(thunderHome, "dist")

	// Check if the frontend build directory exists
	if _, err := os.Stat(frontendPath); os.IsNotExist(err) {
		logger.Warn("Frontend build directory not found, skipping static file handler registration",
			log.String("path", frontendPath))
		return
	}

	fs := http.FileServer(http.Dir(frontendPath))

	// Serve static files (e.g., JS, CSS)
	mux.Handle("/static/", fs)
	mux.Handle("/favicon.ico", fs)
	mux.Handle("/manifest.json", fs)

	// Serve index.html for all other frontend routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only serve index.html for GET requests
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}

		indexPath := path.Join(frontendPath, "index.html")
		http.ServeFile(w, r, indexPath)
	})
}
