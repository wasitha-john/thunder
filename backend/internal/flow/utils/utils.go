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

// Package utils provides utility functions for flow processing.
package utils

import (
	"fmt"

	"github.com/asgardeo/thunder/internal/executor/authassert"
	"github.com/asgardeo/thunder/internal/executor/basicauth"
	"github.com/asgardeo/thunder/internal/executor/githubauth"
	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/flow/jsonmodel"
	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/config"
)

// BuildGraphFromDefinition builds a graph from a graph definition json.
func BuildGraphFromDefinition(definition *jsonmodel.GraphDefinition) (model.GraphInterface, error) {
	if definition == nil || len(definition.Nodes) == 0 {
		return nil, fmt.Errorf("graph definition is nil or has no nodes")
	}

	// Create a graph
	g := model.NewGraph(definition.ID)

	// Map to track which nodes have incoming edges
	hasIncomingEdge := make(map[string]bool)

	// First, mark all nodes that have incoming edges
	for _, targetIDs := range definition.Edges {
		for _, targetID := range targetIDs {
			hasIncomingEdge[targetID] = true
		}
	}

	// Find the start node (node without incoming edges)
	startNodeID := ""
	for _, node := range definition.Nodes {
		if !hasIncomingEdge[node.ID] {
			startNodeID = node.ID
			break
		}
	}

	// If no start node found, fallback to the first node
	if startNodeID == "" && len(definition.Nodes) > 0 {
		startNodeID = definition.Nodes[0].ID
	}

	// Validate that we have a valid start node
	if startNodeID == "" {
		return nil, fmt.Errorf("no valid start node found in the graph definition")
	}

	// Add all nodes to the graph
	for _, nodeDef := range definition.Nodes {
		isStartNode := (nodeDef.ID == startNodeID)
		isFinalNode := (nodeDef.Type == string(constants.AuthSuccessNode))

		// Construct a new node
		node := model.NewNode(nodeDef.ID, nodeDef.Type, isStartNode, isFinalNode)

		// Convert and set input data from definition
		inputData := make([]model.InputData, len(nodeDef.InputData))
		for i, input := range nodeDef.InputData {
			inputData[i] = model.InputData{
				Name:     input.Name,
				Type:     input.Type,
				Required: input.Required,
			}
		}
		node.SetInputData(inputData)

		// Set the executor if defined
		if nodeDef.Executor != "" {
			executor, err := getExecutorByName(nodeDef.Executor)
			if err != nil {
				return nil, fmt.Errorf("error while getting executor %s: %w", nodeDef.Executor, err)
			}
			node.SetExecutor(executor)
		} else if nodeDef.Type == string(constants.AuthSuccessNode) {
			// Assign AuthAssertExecutor for authentication success node if no executor is explicitly defined.
			executor, err := getExecutorByName("AuthAssertExecutor")
			if err != nil {
				return nil, fmt.Errorf("error while getting default AuthAssertExecutor: %w", err)
			}
			node.SetExecutor(executor)
		}

		err := g.AddNode(node)
		if err != nil {
			return nil, fmt.Errorf("failed to add node %s to the graph: %w", nodeDef.ID, err)
		}
	}

	err := g.SetStartNodeID(startNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to set start node ID: %w", err)
	}

	// Add all edges to the graph
	for sourceID, targetIDs := range definition.Edges {
		for _, targetID := range targetIDs {
			err := g.AddEdge(sourceID, targetID)
			if err != nil {
				return nil, fmt.Errorf("failed to add edge from %s to %s: %w", sourceID, targetID, err)
			}
		}
	}

	// Set PreviousNodeID and NextNodeID based on edges
	for fromNodeID, toNodeIDs := range g.GetEdges() {
		if len(toNodeIDs) > 0 {
			// Set the NextNodeID for the source node
			if sourceNode, exists := g.GetNode(fromNodeID); exists {
				sourceNode.SetNextNodeID(toNodeIDs[0])
				// Update the source node in the graph
				err := g.AddNode(sourceNode)
				if err != nil {
					return nil, fmt.Errorf("failed to update source node %s in the graph: %w", fromNodeID, err)
				}
			}

			// Set the PreviousNodeID for each target node
			for _, toNodeID := range toNodeIDs {
				if targetNode, exists := g.GetNode(toNodeID); exists {
					targetNode.SetPreviousNodeID(fromNodeID)
					// Update the target node in the graph
					err := g.AddNode(targetNode)
					if err != nil {
						return nil, fmt.Errorf("failed to update target node %s in the graph: %w", toNodeID, err)
					}
				}
			}
		}
	}

	return g, nil
}

// getExecutorByName constructs an executor by its name.
func getExecutorByName(name string) (model.ExecutorInterface, error) {
	if name == "" {
		return nil, fmt.Errorf("executor name cannot be empty")
	}

	// TODO: When the graph persistence is implemented, this should be moved to graph construction logic
	//  from the stored graph model (at DB).
	//  Building the graph at this layer will only construct the graph structure adding the executors by name.
	//  If needed, can do a validation to ensure the executor exists in the system.
	//  Stored data will only contain the executor name (or id), and the executor will be loaded
	//  from the available executors in the system based on the name during runtime.
	var executor model.ExecutorInterface
	switch name {
	case "BasicAuthExecutor":
		config, err := getExecutorConfig("BasicAuthExecutor")
		if err != nil {
			return nil, fmt.Errorf("error while getting BasicAuthExecutor config: %w", err)
		}
		executor = basicauth.NewBasicAuthExecutor("basic-auth-executor", config.Name)
	case "GithubAuthExecutor":
		githubConfig, err := getExecutorConfig("GithubAuthExecutor")
		if err != nil {
			return nil, fmt.Errorf("error while getting GithubAuthExecutor config: %w", err)
		}
		executor = githubauth.NewGithubOIDCAuthExecutor(githubConfig)
	case "AuthAssertExecutor":
		executor = authassert.NewAuthAssertExecutor("auth-assert-executor", "AuthAssertExecutor")
	default:
		return nil, fmt.Errorf("executor with name %s not found", name)
	}

	if executor == nil {
		return nil, fmt.Errorf("executor with name %s could not be created", name)
	}
	return executor, nil
}

// getExecutorConfig retrieves the configuration for an executor by its name.
func getExecutorConfig(name string) (*config.Executor, error) {
	authExecConfigs := config.GetThunderRuntime().Config.Flow.Authn.Executors

	if len(authExecConfigs) == 0 {
		return nil, fmt.Errorf("no auth executors configured in the system")
	}

	for _, cfg := range authExecConfigs {
		if cfg.Name == name {
			return &cfg, nil
		}
	}

	return nil, fmt.Errorf("auth executor with name %s not found", name)
}
