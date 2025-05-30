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

package model

import (
	"github.com/asgardeo/thunder/internal/flow/constants"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
)

// NodeResponse represents the response from a node execution
type NodeResponse struct {
	Status         constants.FlowStatus   `json:"status"`
	Type           constants.FlowStepType `json:"type"`
	Error          string                 `json:"error,omitempty"`
	RequiredData   []InputData            `json:"required_data,omitempty"`
	AdditionalInfo map[string]string      `json:"additional_info,omitempty"`
	Assertion      string                 `json:"assertion,omitempty"`
}

// NodeInterface defines the interface for nodes in the graph
type NodeInterface interface {
	Execute(ctx *FlowContext) (*NodeResponse, *serviceerror.ServiceError)
	GetID() string
	GetType() string
	IsStartNode() bool
	SetAsStartNode(isStart bool)
	IsFinalNode() bool
	SetAsFinalNode(isFinal bool)
	GetNextNodeID() string
	SetNextNodeID(nextNodeID string)
	GetPreviousNodeID() string
	SetPreviousNodeID(previousNodeID string)
	GetInputData() []InputData
	SetInputData(inputData []InputData)
	GetExecutorConfig() *ExecutorConfig
	SetExecutorConfig(executorConfig *ExecutorConfig)
	GetExecutor() ExecutorInterface
	SetExecutor(executor ExecutorInterface)
}

// Node implements the NodeInterface
type Node struct {
	id             string
	_type          string
	isStartNode    bool
	isFinalNode    bool
	nextNodeID     string
	previousNodeID string
	inputData      []InputData
	executorConfig *ExecutorConfig
}

// NewNode creates a new Node with the given parameters
func NewNode(id string, _type string, isStartNode bool, isFinalNode bool) NodeInterface {
	return &Node{
		id:             id,
		_type:          _type,
		isStartNode:    isStartNode,
		isFinalNode:    isFinalNode,
		nextNodeID:     "",
		previousNodeID: "",
		executorConfig: nil,
	}
}

// Execute executes the node's executor
func (n *Node) Execute(ctx *FlowContext) (*NodeResponse, *serviceerror.ServiceError) {
	if n.executorConfig == nil || n.executorConfig.Executor == nil {
		return nil, &constants.ErrorNodeExecutorNotFound
	}

	execResp, err := n.executorConfig.Executor.Execute(ctx)
	if err != nil {
		svcErr := constants.ErrorNodeExecutorExecError
		svcErr.ErrorDescription = "Error executing node executor: " + err.Error()
		return nil, &svcErr
	}
	if execResp == nil {
		return nil, &constants.ErrorNilResponseFromExecutor
	}

	nodeResp := &NodeResponse{
		Error:          execResp.Error,
		RequiredData:   execResp.RequiredData,
		AdditionalInfo: execResp.AdditionalInfo,
		Assertion:      execResp.Assertion,
	}

	if execResp.Status == constants.ExecComplete {
		nodeResp.Status = constants.Complete
		nodeResp.Type = ""
	} else if execResp.Status == constants.ExecUserInputRequired {
		nodeResp.Status = constants.Incomplete
		nodeResp.Type = constants.View
	} else if execResp.Status == constants.ExecExternalRedirection {
		nodeResp.Status = constants.Incomplete
		nodeResp.Type = constants.Redirection
	} else {
		nodeResp.Status = constants.Error
		nodeResp.Type = ""
	}

	return nodeResp, nil
}

// GetID returns the node's ID
func (n *Node) GetID() string {
	return n.id
}

// GetType returns the node's type
func (n *Node) GetType() string {
	return n._type
}

// IsStartNode checks if the node is a start node
func (n *Node) IsStartNode() bool {
	return n.isStartNode
}

// SetAsStartNode sets the node as a start node
func (n *Node) SetAsStartNode(isStart bool) {
	n.isStartNode = isStart
}

// IsFinalNode checks if the node is a final node
func (n *Node) IsFinalNode() bool {
	return n.isFinalNode
}

// SetAsFinalNode sets the node as a final node
func (n *Node) SetAsFinalNode(isFinal bool) {
	n.isFinalNode = isFinal
}

// GetNextNodeID returns the ID of the next node
func (n *Node) GetNextNodeID() string {
	return n.nextNodeID
}

// SetNextNodeID sets the ID of the next node
func (n *Node) SetNextNodeID(nextNodeID string) {
	n.nextNodeID = nextNodeID
}

// GetPreviousNodeID returns the ID of the previous node
func (n *Node) GetPreviousNodeID() string {
	return n.previousNodeID
}

// SetPreviousNodeID sets the ID of the previous node
func (n *Node) SetPreviousNodeID(previousNodeID string) {
	n.previousNodeID = previousNodeID
}

// GetInputData returns the input data for the node
func (n *Node) GetInputData() []InputData {
	return n.inputData
}

// SetInputData sets the input data for the node
func (n *Node) SetInputData(inputData []InputData) {
	n.inputData = inputData
}

// GetExecutorConfig returns the executor configuration for the node
func (n *Node) GetExecutorConfig() *ExecutorConfig {
	return n.executorConfig
}

// SetExecutorConfig sets the executor configuration for the node
func (n *Node) SetExecutorConfig(executorConfig *ExecutorConfig) {
	n.executorConfig = executorConfig
}

// GetExecutor returns the executor associated with the node
func (n *Node) GetExecutor() ExecutorInterface {
	if n.executorConfig == nil {
		return nil
	}
	return n.executorConfig.Executor
}

// SetExecutor sets the executor for the node
func (n *Node) SetExecutor(executor ExecutorInterface) {
	if n.executorConfig == nil {
		n.executorConfig = &ExecutorConfig{}
		n.executorConfig.Name = executor.GetName()
	}
	n.executorConfig.Executor = executor
}

// PromptNode represents a node that only takes user input
type PromptNode struct {
	*Node
}

// TaskExecutionNode represents a node that executes a task
type TaskExecutionNode struct {
	*Node
}
