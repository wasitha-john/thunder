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
)

// DecisionNode represents a node that makes decisions based on input data.
type DecisionNode struct {
	*Node
}

// NewDecisionNode creates a new DecisionNode with the given details.
func NewDecisionNode(id string, isStartNode bool, isFinalNode bool) NodeInterface {
	return &DecisionNode{
		Node: &Node{
			id:               id,
			_type:            constants.NodeTypeDecision,
			isStartNode:      isStartNode,
			isFinalNode:      isFinalNode,
			nextNodeList:     []string{},
			previousNodeList: []string{},
			inputData:        []InputData{},
			executorConfig:   nil,
		},
	}
}

// Execute executes the decision node logic based on the current context.
func (n *DecisionNode) Execute(ctx *NodeContext) (*NodeResponse, *serviceerror.ServiceError) {
	triggeredActionID := ctx.CurrentActionID
	if triggeredActionID != "" {
		return n.TriggerAction(ctx, triggeredActionID)
	}

	return n.PrepareActionInput(ctx, triggeredActionID)
}

// TriggerAction processes the action triggered by the user and determines the next node to transition to.
func (n *DecisionNode) TriggerAction(ctx *NodeContext, actionID string) (*NodeResponse,
	*serviceerror.ServiceError) {
	nextNodeIDs := n.GetNextNodeList()
	if len(nextNodeIDs) == 0 {
		return &NodeResponse{
			Status:        constants.NodeStatusFailure,
			Type:          "",
			FailureReason: "No next nodes defined for the decision node.",
		}, nil
	}

	var nextNodeID string
	for _, nextNodeIDCandidate := range nextNodeIDs {
		if nextNodeIDCandidate == actionID {
			nextNodeID = nextNodeIDCandidate
			break
		}
	}
	if nextNodeID == "" {
		return &NodeResponse{
			Status:        constants.NodeStatusFailure,
			Type:          "",
			FailureReason: "No matching next node found for the triggered action ID.",
		}, nil
	}

	return &NodeResponse{
		Status:     constants.NodeStatusComplete,
		Type:       "",
		NextNodeID: nextNodeID,
	}, nil
}

// PrepareActionInput prepares the input for the action to be triggered by the user.
func (n *DecisionNode) PrepareActionInput(ctx *NodeContext, actionID string) (*NodeResponse,
	*serviceerror.ServiceError) {
	actions := n.getActionsList()
	if len(actions) == 0 {
		svcErr := constants.ErrorNoActionsDefinedForNode
		svcErr.ErrorDescription = "No outgoing edges defined for the decision node."
		return nil, &svcErr
	}

	return &NodeResponse{
		Status:         constants.NodeStatusIncomplete,
		Type:           constants.NodeResponseTypeView,
		Actions:        actions,
		FailureReason:  "",
		RequiredData:   make([]InputData, 0),
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}, nil
}

// getActionsList retrieves the list of actions available for the decision node.
func (n *DecisionNode) getActionsList() []Action {
	actions := []Action{}
	for _, nextNodeID := range n.GetNextNodeList() {
		action := Action{
			Type: constants.ActionTypeView,
			ID:   nextNodeID,
		}
		actions = append(actions, action)
	}
	return actions
}
