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

// Package constants defines the constants used in the flow execution service and engine.
package constants

// FlowStatus defines the status of a flow execution.
type FlowStatus string

const (
	// Complete indicates that the flow execution is complete.
	Complete FlowStatus = "COMPLETE"
	// Incomplete indicates that the flow execution is incomplete.
	Incomplete FlowStatus = "INCOMPLETE"
	// PromptOnly indicates that the flow execution is in a prompt-only state.
	PromptOnly FlowStatus = "PROMPT_ONLY"
	// Error indicates that there was an error during the flow execution.
	Error FlowStatus = "ERROR"
)

// FlowStepType defines the type of a step in the flow execution.
type FlowStepType string

const (
	// View represents a step in the flow that requires user interaction.
	View FlowStepType = "VIEW"
	// Redirection represents a step in the flow that redirects the user to another URL.
	Redirection FlowStepType = "REDIRECTION"
)

// NodeType defines the node types in the flow execution.
type NodeType string

const (
	// AuthSuccessNode represents a node that does auth assertion
	AuthSuccessNode NodeType = "AUTHENTICATION_SUCCESS"
	// TaskExecutionNode represents a task execution node
	TaskExecutionNode NodeType = "TASK_EXECUTION"
	// PromptOnlyNode represents a prompt-only node
	PromptOnlyNode NodeType = "PROMPT_ONLY"
	// DecisionNode represents a decision node
	DecisionNode NodeType = "DECISION"
)

// ExecutorStatus defines the status of an executor in the flow execution.
type ExecutorStatus string

const (
	// ExecComplete indicates that the executor has completed its execution successfully.
	ExecComplete ExecutorStatus = "COMPLETE"
	// ExecIncomplete indicates that the executor has not completed its execution.
	ExecIncomplete ExecutorStatus = "INCOMPLETE"
	// ExecUserInputRequired indicates that the executor requires user input to proceed.
	ExecUserInputRequired ExecutorStatus = "USER_INPUT_REQUIRED"
	// ExecExternalRedirection indicates that the executor is redirecting to an external URL.
	ExecExternalRedirection ExecutorStatus = "EXTERNAL_REDIRECTION"
	// ExecError indicates that there was an error during the executor's execution.
	ExecError ExecutorStatus = "ERROR"
	// ExecUserError indicates that there was a user error during the executor's execution.
	ExecUserError ExecutorStatus = "USER_ERROR"
)

// ExecutorResponseType defines the type of response from an executor in the flow execution.
type ExecutorResponseType string

const (
	// ExecView indicates that the executor response is a view type, requiring user interaction.
	ExecView ExecutorResponseType = "VIEW"
	// ExecRedirection indicates that the executor response is a redirection type, redirecting to another URL.
	ExecRedirection ExecutorResponseType = "REDIRECTION"
)

const (
	// DataRedirectURL is the key used to store the redirect URL in the flow context.
	DataRedirectURL = "redirect_url"
)
