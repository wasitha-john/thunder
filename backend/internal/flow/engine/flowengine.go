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

// Package engine provides the flow engine for orchestrating flow executions.
package engine

import (
	"errors"
	"sync"

	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/system/log"
)

var (
	instance *FlowEngine
	once     sync.Once
)

// FlowEngineInterface defines the interface for the flow engine.
type FlowEngineInterface interface {
	Execute(ctx *model.FlowContext) (model.FlowStep, error)
}

// FlowEngine is the main engine implementation for orchestrating flow executions.
type FlowEngine struct{}

// GetFlowEngine returns a singleton instance of FlowEngine.
func GetFlowEngine() FlowEngineInterface {
	once.Do(func() {
		instance = &FlowEngine{}
	})
	return instance
}

// Execute executes a step in the flow
func (e *FlowEngine) Execute(ctx *model.FlowContext) (model.FlowStep, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowEngine"))

	flowStep := model.FlowStep{
		FlowID: ctx.FlowID,
	}

	graph := ctx.Graph
	if graph == nil {
		return flowStep, errors.New("flow graph is nil")
	}

	currentNode := ctx.CurrentNode
	if currentNode == nil {
		logger.Debug("Current node is nil. Setting the start node as the current node.")
		var ok bool
		currentNode, ok = graph.GetNode(graph.GetStartNodeID())
		if !ok {
			return flowStep, errors.New("start node not found in the graph")
		}
		ctx.CurrentNode = currentNode
	}

	// Execute the graph nodes until a terminal condition is met or currentNode is nil
	for currentNode != nil {
		logger.Debug("Executing node", log.String("nodeID", currentNode.GetID()),
			log.String("nodeType", currentNode.GetType()))

		// Execute the current node
		nodeResp, err := currentNode.Execute(ctx)
		if err != nil {
			return flowStep, err
		}

		// Update the context with the current node response
		ctx.CurrentNodeResponse = nodeResp

		if nodeResp.Status == "" {
			return flowStep, errors.New("node response status is empty")
		}
		if nodeResp.Status == constants.FlowStatusComplete {
			// If the node returns complete status, move to the next node and let it execute.
			currentNode, err = e.resolveToNextNode(ctx.Graph, currentNode)
			if err != nil {
				return flowStep, errors.New("error moving to next node: " + err.Error())
			}
			ctx.CurrentNode = currentNode
			continue
		} else if nodeResp.Status == constants.FlowStatusIncomplete {
			// If the node returns incomplete status, set the flow step details and return.
			// The same node will be executed again in the next request with the required data.
			if nodeResp.Type == constants.FlowStepTypeRedirection {
				err := e.resolveStepForRedirection(nodeResp, &flowStep)
				if err != nil {
					return flowStep, errors.New("error resolving step for redirection: " + err.Error())
				}

				return flowStep, nil
			} else if nodeResp.Type == constants.FlowStepTypeView {
				err := e.resolveStepDetailsForPrompt(nodeResp, &flowStep)
				if err != nil {
					return flowStep, errors.New("error resolving step details for prompt: " + err.Error())
				}

				return flowStep, nil
			} else {
				return flowStep, errors.New("unsupported response type returned from the node: " + nodeResp.Type)
			}
		} else if nodeResp.Status == constants.FlowStatusPromptOnly {
			// If it is a prompt only node, set to the next node and return the current flow step.
			// The next node will be executed in the next request with the requested data.
			currentNode, err = e.resolveToNextNode(ctx.Graph, currentNode)
			if err != nil {
				return flowStep, errors.New("error moving to next node: " + err.Error())
			}
			ctx.CurrentNode = currentNode
			err := e.resolveStepDetailsForPrompt(nodeResp, &flowStep)
			if err != nil {
				return flowStep, errors.New("error resolving step details for prompt: " + err.Error())
			}

			return flowStep, nil
		} else if nodeResp.Status == constants.FlowStatusError {
			// If the node returns an error status, set the flow step status to error and return.
			flowStep.Status = constants.FlowStatusError
			if nodeResp.Error != "" {
				return flowStep, errors.New("error returned from the node: " + nodeResp.Error)
			}
			return flowStep, errors.New("error returned from the node")
		} else {
			// If the node returns an unsupported status, return an error.
			return flowStep, errors.New("unsupported status returned from the node: " + nodeResp.Status)
		}
	}

	// If we reach here, it means the flow has been executed successfully.
	flowStep.Status = constants.FlowStatusComplete

	// If the current node response has an assertion, set it in the flow step.
	if ctx.CurrentNodeResponse != nil && ctx.CurrentNodeResponse.Assertion != "" {
		flowStep.Assertion = ctx.CurrentNodeResponse.Assertion
	}

	return flowStep, nil
}

func (e *FlowEngine) resolveToNextNode(graph model.GraphInterface,
	currentNode model.NodeInterface) (model.NodeInterface, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowEngine"))

	nextNodeID := currentNode.GetNextNodeID()
	if nextNodeID == "" {
		logger.Debug("No next node found. Returning nil.")
		return nil, nil
	}

	nextNode, ok := graph.GetNode(nextNodeID)
	if !ok {
		return nil, errors.New("next node not found in the graph")
	}

	logger.Debug("Moving to next node", log.String("nextNodeID", nextNode.GetID()))
	return nextNode, nil
}

func (e *FlowEngine) resolveStepForRedirection(nodeResp *model.ExecutorResponse, flowStep *model.FlowStep) error {
	if nodeResp == nil {
		return errors.New("node response is nil")
	}
	if len(nodeResp.AdditionalInfo) == 0 {
		return errors.New("additional info not found in the node response")
	}
	if nodeResp.AdditionalInfo[constants.DataRedirectURL] == "" {
		return errors.New("redirect URL not found in the additional info")
	}

	if flowStep.AdditionalInfo == nil {
		flowStep.AdditionalInfo = make(map[string]string)
		flowStep.AdditionalInfo = nodeResp.AdditionalInfo
	} else {
		// Append to the existing additional info
		for key, value := range nodeResp.AdditionalInfo {
			flowStep.AdditionalInfo[key] = value
		}
	}

	flowStep.Status = constants.FlowStatusIncomplete
	flowStep.Type = constants.FlowStepTypeRedirection
	return nil
}

func (e *FlowEngine) resolveStepDetailsForPrompt(nodeResp *model.ExecutorResponse, flowStep *model.FlowStep) error {
	if nodeResp == nil {
		return errors.New("node response is nil")
	}
	if len(nodeResp.RequiredData) == 0 {
		return errors.New("required data not found in the node response")
	}

	if flowStep.InputData == nil {
		flowStep.InputData = make([]model.InputData, 0)
		flowStep.InputData = nodeResp.RequiredData
	} else {
		// Append to the existing input data
		flowStep.InputData = append(flowStep.InputData, nodeResp.RequiredData...)
	}

	flowStep.Status = constants.FlowStatusPromptOnly
	flowStep.Type = constants.FlowStepTypeView
	return nil
}

// TODO: Need to set actions when adding support for Decision nodes.
