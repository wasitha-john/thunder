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

// Package flowmgt provides the flow management service implementation.
package flowmgt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/asgardeo/thunder/internal/flow/common/constants"
	"github.com/asgardeo/thunder/internal/flow/common/jsonmodel"
	"github.com/asgardeo/thunder/internal/flow/common/model"
	"github.com/asgardeo/thunder/internal/flow/common/utils"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// FlowMgtServiceInterface defines the interface for the flow management service.
type FlowMgtServiceInterface interface {
	init() error
	RegisterGraph(graphID string, g model.GraphInterface)
	GetGraph(graphID string) (model.GraphInterface, bool)
	IsValidGraphID(graphID string) bool
}

// flowMgtService is the implementation of FlowMgtServiceInterface.
type flowMgtService struct {
	graphs map[string]model.GraphInterface
	mu     sync.Mutex
}

func newFlowMgtService() (FlowMgtServiceInterface, error) {
	flowMgtInstance := &flowMgtService{
		graphs: make(map[string]model.GraphInterface),
		mu:     sync.Mutex{},
	}
	err := flowMgtInstance.init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize flow management service: %w", err)
	}

	err = flowMgtInstance.validateDefaultFlowConfigs()
	if err != nil {
		return nil, errors.New("failed to validate default flow configurations: " + err.Error())
	}
	return flowMgtInstance, nil
}

// GetFlowMgtService returns a singleton instance of FlowMgtServiceInterface.
// [Deprecated: use dependency injection to get the instance instead.]
// Remove this once the application service is refactored to use DI.
func GetFlowMgtService() FlowMgtServiceInterface {
	flowMgtService, err := newFlowMgtService()
	if err != nil {
		log.GetLogger().Fatal("Failed to initialize FlowMgtService", log.Error(err))
	}
	return flowMgtService
}

// Init initializes the FlowMgtService by loading graph configurations into runtime.
func (s *flowMgtService) init() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowMgtService"))
	logger.Debug("Initializing the flow management service")

	configDir := config.GetThunderRuntime().Config.Flow.GraphDirectory
	if configDir == "" {
		logger.Info("Graph directory is not set. No graphs will be loaded.")
		return nil
	}

	configDir = filepath.Join(config.GetThunderRuntime().ThunderHome, configDir)
	configDir = filepath.Clean(configDir)

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
	flowGraphs := make(map[string]model.GraphInterface)
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
		if logger.IsDebugEnabled() {
			jsonString, err := graphModel.ToJSON()
			if err != nil {
				logger.Warn("Failed to convert graph model to JSON", log.String("filePath", filePath), log.Error(err))
			} else {
				logger.Debug("Graph model loaded successfully", log.String("graphID", graphModel.GetID()),
					log.String("json", jsonString))
			}
		}

		// Append graph to the flowGraphs map
		flowGraphs[graphModel.GetID()] = graphModel
	}

	// Register all loaded graphs
	inferredGraphCount := 0
	for graphID, graph := range flowGraphs {
		// Create and register the equivalent registration graph if not found already.
		registrationGraphID := s.getRegistrationGraphID(graphID)
		_, exists := s.graphs[registrationGraphID]
		if !exists && graph.GetType() == constants.FlowTypeAuthentication {
			if err := s.createAndRegisterRegistrationGraph(registrationGraphID, graph, logger); err != nil {
				logger.Error("Failed creating registration graph", log.String("graphID", graphID), log.Error(err))
				continue
			}
			inferredGraphCount++
		}

		logger.Debug("Registering graph", log.String("graphType", string(graph.GetType())),
			log.String("graphID", graphID))
		s.RegisterGraph(graphID, graph)
	}

	logger.Debug("Flow management service initialized successfully", log.Int("configuredGraphCount", len(flowGraphs)),
		log.Int("inferredGraphCount", inferredGraphCount))

	return nil
}

// RegisterGraph registers a graph with the FlowMgtService by its ID.
func (s *flowMgtService) RegisterGraph(graphID string, g model.GraphInterface) {
	s.graphs[graphID] = g
}

// GetGraph retrieves a graph by its ID
func (s *flowMgtService) GetGraph(graphID string) (model.GraphInterface, bool) {
	g, ok := s.graphs[graphID]
	return g, ok
}

// IsValidGraphID checks if the provided graph ID is valid and exists in the service.
func (s *flowMgtService) IsValidGraphID(graphID string) bool {
	if graphID == "" {
		return false
	}
	_, exists := s.graphs[graphID]
	return exists
}

// getRegistrationGraphID constructs the registration graph ID from the auth graph ID.
func (s *flowMgtService) getRegistrationGraphID(authGraphID string) string {
	return constants.RegistrationFlowGraphPrefix + strings.TrimPrefix(authGraphID, constants.AuthFlowGraphPrefix)
}

// createAndRegisterRegistrationGraph creates a registration graph from an authentication graph and registers it.
func (s *flowMgtService) createAndRegisterRegistrationGraph(registrationGraphID string, authGraph model.GraphInterface,
	logger *log.Logger) error {
	registrationGraph, err := s.createRegistrationGraph(registrationGraphID, authGraph)
	if err != nil {
		return fmt.Errorf("failed to infer registration graph: %w", err)
	}

	if logger.IsDebugEnabled() {
		registrationGraphJSON, err := registrationGraph.ToJSON()
		if err != nil {
			logger.Warn("Failed to convert graph model to JSON", log.String("graphID", registrationGraphID),
				log.Error(err))
		} else {
			logger.Debug("Graph model loaded successfully", log.String("graphID", registrationGraph.GetID()),
				log.String("json", registrationGraphJSON))
		}
	}

	logger.Debug("Registering inferred registration graph", log.String("graphID", registrationGraph.GetID()))
	s.RegisterGraph(registrationGraph.GetID(), registrationGraph)
	return nil
}

// createRegistrationGraph creates a registration graph from an authentication graph.
func (s *flowMgtService) createRegistrationGraph(registrationGraphID string,
	authGraph model.GraphInterface) (model.GraphInterface, error) {
	// Create a new graph from the authentication graph
	registrationGraph := model.NewGraph(registrationGraphID, constants.FlowTypeRegistration)

	nodesCopy, err := sysutils.DeepCopyMapOfClonables(authGraph.GetNodes())
	if err != nil {
		return nil, fmt.Errorf("failed to deep copy nodes from auth graph: %w", err)
	}
	registrationGraph.SetNodes(nodesCopy)
	registrationGraph.SetEdges(sysutils.DeepCopyMapOfStringSlices(authGraph.GetEdges()))

	err = registrationGraph.SetStartNode(authGraph.GetStartNodeID())
	if err != nil {
		return nil, fmt.Errorf("failed to set start node for registration graph: %w", err)
	}

	// Find authentication success nodes to insert provisioning before them
	authSuccessNodeID := ""
	nodes := registrationGraph.GetNodes()
	for nodeID, node := range nodes {
		if node.IsFinalNode() {
			authSuccessNodeID = nodeID
			break
		}
	}
	if authSuccessNodeID == "" {
		return nil, fmt.Errorf("no authentication success node found in the authentication graph")
	}

	// Create and add provisioning node
	provisioningNode, err := s.createProvisioningNode()
	if err != nil {
		return nil, fmt.Errorf("failed to create provisioning node: %w", err)
	}
	err = registrationGraph.AddNode(provisioningNode)
	if err != nil {
		return nil, fmt.Errorf("failed to add provisioning node to registration graph: %w", err)
	}

	// Modify the edges that lead to the auth success node to point to the provisioning node
	for fromNodeID, toNodeIDs := range registrationGraph.GetEdges() {
		for _, toNodeID := range toNodeIDs {
			if toNodeID == authSuccessNodeID {
				err := registrationGraph.RemoveEdge(fromNodeID, toNodeID)
				if err != nil {
					return nil, fmt.Errorf("failed to remove edge from %s to %s: %w", fromNodeID, toNodeID, err)
				}

				err = registrationGraph.AddEdge(fromNodeID, provisioningNode.GetID())
				if err != nil {
					return nil, fmt.Errorf("failed to add edge from %s to provisioning node: %w", fromNodeID, err)
				}
			}
		}
	}

	// Add an edge from the provisioning node to the auth success node
	err = registrationGraph.AddEdge(provisioningNode.GetID(), authSuccessNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to add edge from provisioning node to auth success node: %w", err)
	}

	return registrationGraph, nil
}

// createProvisioningNode creates a provisioning node that leads to the specified auth success node
func (s *flowMgtService) createProvisioningNode() (model.NodeInterface, error) {
	provisioningNode, err := model.NewNode(
		"provisioning",
		string(constants.NodeTypeTaskExecution),
		false,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create provisioning node: %w", err)
	}

	execConfig := &model.ExecutorConfig{
		Name:       "ProvisioningExecutor",
		Properties: make(map[string]string),
	}
	provisioningNode.SetExecutorConfig(execConfig)

	return provisioningNode, nil
}

// validateDefaultFlowConfigs validates the default flow configurations.
func (s *flowMgtService) validateDefaultFlowConfigs() error {
	flowConfig := config.GetThunderRuntime().Config.Flow

	// Validate auth flow.
	if flowConfig.Authn.DefaultFlow == "" {
		return errors.New("default authentication flow is not configured")
	}
	if !s.IsValidGraphID(flowConfig.Authn.DefaultFlow) {
		return errors.New("default authentication flow graph ID is invalid")
	}

	return nil
}
