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

const (
	// FlowStatusComplete indicates that the flow execution is complete.
	FlowStatusComplete = "COMPLETE"
	// FlowStatusIncomplete indicates that the flow execution is incomplete.
	FlowStatusIncomplete = "INCOMPLETE"
	// FlowStatusPromptOnly indicates that the flow execution is in a prompt-only state.
	FlowStatusPromptOnly = "PROMPT_ONLY"
	// FlowStatusError indicates that there was an error during the flow execution.
	FlowStatusError = "ERROR"

	// FlowStepTypeView represents a step in the flow that requires user interaction.
	FlowStepTypeView = "VIEW"
	// FlowStepTypeRedirection represents a step in the flow that redirects the user to another URL.
	FlowStepTypeRedirection = "REDIRECTION"
)

const (
	// NodeTypeTaskExecution represents a task execution node
	NodeTypeTaskExecution = "TASK_EXECUTION"
	// NodeTypePromptOnly represents a prompt-only node
	NodeTypePromptOnly = "PROMPT_ONLY"
	// NodeTypeDecision represents a decision node
	NodeTypeDecision = "DECISION"
)

const (
	// ExecutorStatusComplete indicates that the executor has completed its execution successfully.
	ExecutorStatusComplete = "COMPLETE"
	// ExecutorStatusUserInputRequired indicates that the executor requires user input to proceed.
	ExecutorStatusUserInputRequired = "USER_INPUT_REQUIRED"
	// ExecutorStatusExternalRedirection indicates that the executor is redirecting to an external URL.
	ExecutorStatusExternalRedirection = "EXTERNAL_REDIRECTION"
	// ExecutorStatusError indicates that there was an error during the executor's execution.
	ExecutorStatusError = "ERROR"
	// ExecutorStatusUserError indicates that there was a user error during the executor's execution.
	ExecutorStatusUserError = "USER_ERROR"
)

const (
	// DataRedirectURL is the key used to store the redirect URL in the flow context.
	DataRedirectURL = "redirect_url"
)
