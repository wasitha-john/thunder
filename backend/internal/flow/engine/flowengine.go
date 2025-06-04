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
	"github.com/asgardeo/thunder/internal/flow/utils"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

var (
	instance *FlowEngine
	once     sync.Once
)

// FlowEngineInterface defines the interface for the flow engine.
type FlowEngineInterface interface {
	Execute(ctx *model.EngineContext) (model.FlowStep, *serviceerror.ServiceError)
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
func (fe *FlowEngine) Execute(ctx *model.EngineContext) (model.FlowStep, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "FlowEngine"))

	flowStep := model.FlowStep{
		FlowID: ctx.FlowID,
	}

	graph := ctx.Graph
	if graph == nil {
		return flowStep, &constants.ErrorFlowGraphNotInitialized
	}

	currentNode := ctx.CurrentNode
	if currentNode == nil {
		logger.Debug("Current node is nil. Setting the start node as the current node.")
		var ok bool
		currentNode, ok = graph.GetNode(graph.GetStartNodeID())
		if !ok {
			return flowStep, &constants.ErrorStartNodeNotFoundInGraph
		}
		ctx.CurrentNode = currentNode
	}

	// Execute the graph nodes until a terminal condition is met or currentNode is nil
	for currentNode != nil {
		logger.Debug("Executing node", log.String("nodeID", currentNode.GetID()),
			log.String("nodeType", currentNode.GetType()))

		// Set the node executor if it is not already set
		if currentNode.GetExecutor() == nil {
			logger.Debug("Executor not set for the node. Constructing executor.",
				log.String("nodeID", currentNode.GetID()))

			executor, err := utils.GetExecutorByName(currentNode.GetExecutorConfig())
			if err != nil {
				logger.Error("Error constructing executor for node", log.String("nodeID", currentNode.GetID()),
					log.String("executorName", currentNode.GetExecutorConfig().Name), log.Error(err))
				return flowStep, &constants.ErrorConstructingNodeExecutor
			}
			currentNode.SetExecutor(executor)
		}

		// Construct the current node context
		nodeCtx := &model.NodeContext{
			FlowID:            ctx.FlowID,
			AppID:             ctx.AppID,
			NodeInputData:     ctx.CurrentNode.GetInputData(),
			UserInputData:     ctx.UserInputData,
			AuthenticatedUser: ctx.AuthenticatedUser,
		}

		// Execute the current node
		nodeResp, nodeErr := currentNode.Execute(nodeCtx)
		if nodeErr != nil {
			return flowStep, nodeErr
		}

		// Update the context with the current node response
		ctx.CurrentNodeResponse = nodeResp
		ctx.AuthenticatedUser = nodeCtx.AuthenticatedUser

		if nodeResp.Status == "" {
			return flowStep, &constants.ErrorNodeResponseStatusNotFound
		}
		if nodeResp.Status == constants.NodeStatusComplete {
			// If the node returns complete status, move to the next node and let it execute.
			var err error
			currentNode, err = fe.resolveToNextNode(ctx.Graph, currentNode)
			if err != nil {
				svcErr := constants.ErrorMovingToNextNode
				svcErr.ErrorDescription = "error moving to next node: " + err.Error()
				return flowStep, &svcErr
			}
			ctx.CurrentNode = currentNode
			continue
		} else if nodeResp.Status == constants.NodeStatusIncomplete {
			// If the node returns incomplete status, set the flow step details and return.
			// The same node will be executed again in the next request with the required data.
			if nodeResp.Type == constants.NodeResponseTypeRedirection {
				err := fe.resolveStepForRedirection(nodeResp, &flowStep)
				if err != nil {
					svcErr := constants.ErrorResolvingStepForRedirection
					svcErr.ErrorDescription = "error resolving step for redirection: " + err.Error()
					return flowStep, &svcErr
				}
				return flowStep, nil
			} else if nodeResp.Type == constants.NodeResponseTypeView {
				err := fe.resolveStepDetailsForPrompt(nodeResp, &flowStep)
				if err != nil {
					svcErr := constants.ErrorResolvingStepForPrompt
					svcErr.ErrorDescription = "error resolving step for prompt: " + err.Error()
					return flowStep, &svcErr
				}
				return flowStep, nil
			} else {
				svcErr := constants.ErrorUnsupportedNodeResponseType
				svcErr.ErrorDescription = "unsupported node response type: " + string(nodeResp.Type)
				return flowStep, &svcErr
			}
			// TODO: Handle retry scenarios with nodeResp.Type == constants.NodeResponseTypeRetry
		} else if nodeResp.Status == constants.NodeStatusPromptOnly {
			// If it is a prompt only node, set to the next node and return the current flow step.
			// The next node will be executed in the next request with the requested data.
			var err error
			currentNode, err = fe.resolveToNextNode(ctx.Graph, currentNode)
			if err != nil {
				svcErr := constants.ErrorMovingToNextNode
				svcErr.ErrorDescription = "error moving to next node: " + err.Error()
				return flowStep, &svcErr
			}
			ctx.CurrentNode = currentNode
			err = fe.resolveStepDetailsForPrompt(nodeResp, &flowStep)
			if err != nil {
				svcErr := constants.ErrorResolvingStepForPrompt
				svcErr.ErrorDescription = "error resolving step details for prompt: " + err.Error()
				return flowStep, &svcErr
			}
			return flowStep, nil
		} else if nodeResp.Status == constants.NodeStatusFailure {
			// If the node returns a failure status, set the flow step status to failure and return the step.
			flowStep.Status = constants.FlowStatusError
			flowStep.FailureReason = nodeResp.FailureReason
			return flowStep, nil
		} else {
			// If the node returns an unsupported status, return an error.
			svcErr := constants.ErrorUnsupportedNodeResponseStatus
			svcErr.ErrorDescription = "unsupported status returned from the node: " + string(nodeResp.Status)
			return flowStep, &svcErr
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

func (fe *FlowEngine) resolveToNextNode(graph model.GraphInterface,
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

func (fe *FlowEngine) resolveStepForRedirection(nodeResp *model.NodeResponse, flowStep *model.FlowStep) error {
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

	if flowStep.InputData == nil {
		flowStep.InputData = make([]model.InputData, 0)
		flowStep.InputData = nodeResp.RequiredData
	} else {
		// Append to the existing input data
		flowStep.InputData = append(flowStep.InputData, nodeResp.RequiredData...)
	}

	flowStep.Status = constants.FlowStatusIncomplete
	flowStep.Type = constants.StepTypeRedirection
	return nil
}

func (fe *FlowEngine) resolveStepDetailsForPrompt(nodeResp *model.NodeResponse, flowStep *model.FlowStep) error {
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

	flowStep.Status = constants.FlowStatusIncomplete
	flowStep.Type = constants.StepTypeView
	return nil
}

// TODO: Need to set actions when adding support for Decision nodes.
