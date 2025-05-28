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

// Package dao provides the dao layer for managing flow graphs.
package dao

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/asgardeo/thunder/internal/flow/jsonmodel"
	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/flow/utils"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
)

var (
	instance *FlowDAO
	once     sync.Once
)

// FlowDAOInterface defines the interface for the flow data access object.
type FlowDAOInterface interface {
	Init() error
	RegisterGraph(graphID string, g model.GraphInterface)
	GetGraph(graphID string) (model.GraphInterface, bool)
}

// FlowDAO is the implementation of FlowDAOInterface.
type FlowDAO struct {
	graphs map[string]model.GraphInterface
}

// GetFlowDAO returns a singleton instance of FlowDAOInterface.
func GetFlowDAO() FlowDAOInterface {
	once.Do(func() {
		instance = &FlowDAO{
			graphs: make(map[string]model.GraphInterface),
		}
	})
	return instance
}

// Init initializes the FlowDAO by loading graph configurations into runtime.
func (c *FlowDAO) Init() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowDAO"))
	logger.Info("Initializing the flow DAO layer")

	configDir := config.GetThunderRuntime().Config.Authenticator.GraphDirectory
	if configDir == "" {
		logger.Info("Graph directory is not set. No graphs will be loaded.")
		return nil
	}

	logger.Debug("Loading graphs from config directory", log.String("configDir", configDir))

	files, err := os.ReadDir(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("Config directory does not exist. No graphs will be loaded.",
				log.String("configDir", configDir))
			return nil
		}
		return fmt.Errorf("failed to read config directory %s: %w", configDir, err)
	}

	if len(files) == 0 {
		logger.Info("No graph configuration files found in the configured directory. No graphs will be loaded.")
		return nil
	}
	logger.Debug("Found graph definition files in the graph directory", log.Int("fileCount", len(files)))

	// Process each JSON file in the directory
	for _, file := range files {
		// Skip directories and non-JSON files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			logger.Debug("Skipping non-JSON file or directory",
				log.String("fileName", file.Name()), log.Bool("isDir", file.IsDir()))
			continue
		}
		filePath := filepath.Join(configDir, file.Name())
		filePath = filepath.Clean(filePath)

		// Read the file content
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			logger.Warn("Failed to read graph file", log.String("filePath", filePath), log.Error(err))
			continue
		}

		// Parse the JSON into the flow model
		var jsonGraph jsonmodel.GraphDefinition
		if err := json.Unmarshal(fileContent, &jsonGraph); err != nil {
			logger.Warn("Failed to parse JSON in file", log.String("filePath", filePath), log.Error(err))
			continue
		}

		// Convert the JSON graph definition to the graph model
		graphModel, err := utils.BuildGraphFromDefinition(&jsonGraph)
		if err != nil {
			logger.Warn("Failed to convert graph definition to graph model",
				log.String("filePath", filePath), log.Error(err))
			continue
		}

		// Log the graph model as JSON for debugging
		jsonString, err := graphModel.ToJSON()
		if err != nil {
			logger.Warn("Failed to convert graph model to JSON", log.String("filePath", filePath), log.Error(err))
		} else {
			logger.Debug("Graph model loaded successfully", log.String("graphID", graphModel.GetID()),
				log.String("json", jsonString))
		}

		// Register the graph with the flow DAO
		logger.Debug("Registering a graph", log.String("graphID", graphModel.GetID()))
		c.RegisterGraph(graphModel.GetID(), graphModel)
	}

	return nil
}

// RegisterGraph registers a graph with the FlowDAO by its ID.
func (c *FlowDAO) RegisterGraph(graphID string, g model.GraphInterface) {
	c.graphs[graphID] = g
}

// GetGraph retrieves a graph by its ID
func (c *FlowDAO) GetGraph(graphID string) (model.GraphInterface, bool) {
	g, ok := c.graphs[graphID]
	return g, ok
}
