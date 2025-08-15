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

package model

import (
	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "PromptOnlyNode"

// PromptOnlyNode represents a node that only prompts for input without executing any logic.
type PromptOnlyNode struct {
	*Node
}

// NewPromptOnlyNode creates a new PromptOnlyNode with the given details.
func NewPromptOnlyNode(id string, isStartNode bool, isFinalNode bool) NodeInterface {
	return &PromptOnlyNode{
		Node: &Node{
			id:               id,
			_type:            constants.NodeTypePromptOnly,
			isStartNode:      isStartNode,
			isFinalNode:      isFinalNode,
			nextNodeList:     []string{},
			previousNodeList: []string{},
			inputData:        []InputData{},
			executorConfig:   nil,
		},
	}
}

// Execute executes the prompt-only node logic based on the current context.
func (n *PromptOnlyNode) Execute(ctx *NodeContext) (*NodeResponse, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyNodeID, n.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing prompt-only node")

	nodeResp := &NodeResponse{
		RequiredData:   make([]InputData, 0),
		AdditionalData: make(map[string]string),
		Actions:        make([]Action, 0),
		RuntimeData:    make(map[string]string),
	}

	if n.checkInputData(ctx, nodeResp) {
		logger.Debug("Required input data is not available in the context, returning incomplete response",
			log.Any("requiredData", nodeResp.RequiredData))
		nodeResp.Status = constants.NodeStatusIncomplete
		nodeResp.Type = constants.NodeResponseTypeView
		return nodeResp, nil
	}

	logger.Debug("All required input data is available in the context, proceeding with next steps")
	nodeResp.Status = constants.NodeStatusComplete
	nodeResp.Type = ""
	return nodeResp, nil
}

// checkInputData checks if the required input data is available in the context.
// If not, it appends the required data to the node response and returns true.
// If all required data is available, it returns false.
func (n *PromptOnlyNode) checkInputData(ctx *NodeContext, nodeResp *NodeResponse) bool {
	requiredData := n.GetInputData()
	if len(requiredData) == 0 {
		return false
	}

	if nodeResp.RequiredData == nil {
		nodeResp.RequiredData = make([]InputData, 0)
	}

	if len(ctx.UserInputData) == 0 {
		nodeResp.RequiredData = append(nodeResp.RequiredData, requiredData...)
		return true
	}

	return n.appendRequiredData(ctx, nodeResp, requiredData)
}

// appendRequiredData appends the required input data to the node response if not present in the context.
// returns true if any required data is missing, false otherwise.
func (n *PromptOnlyNode) appendRequiredData(ctx *NodeContext, nodeResp *NodeResponse, requiredData []InputData) bool {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyNodeID, n.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))

	requireData := false
	for _, inputData := range requiredData {
		if _, ok := ctx.UserInputData[inputData.Name]; !ok {
			if inputData.Required {
				requireData = true
			}
			nodeResp.RequiredData = append(nodeResp.RequiredData, inputData)
			logger.Debug("Input data not available in the context",
				log.String("inputDataName", inputData.Name), log.Bool("isRequired", inputData.Required))
		}
	}

	return requireData
}
