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

package constants

import (
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
)

// Client error structs

// APIErrorFlowRequestJSONDecodeError defines the error response for json decode errors.
var APIErrorFlowRequestJSONDecodeError = apierror.ErrorResponse{
	Code:        "FES-60001",
	Message:     "Invalid request payload",
	Description: "Failed to decode request payload",
}

// ErrorNodeResponse defines the error response for errors received from nodes.
var ErrorNodeResponse = serviceerror.ServiceError{
	Code:             "FES-60002",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid node response",
	ErrorDescription: "Error response received from the node",
}

// ErrorInvalidAppID defines the error response for invalid app ID errors.
var ErrorInvalidAppID = serviceerror.ServiceError{
	Code:             "FES-60003",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "Invalid app ID provided in the request",
}

// ErrorInvalidFlowID defines the error response for invalid flow ID errors.
var ErrorInvalidFlowID = serviceerror.ServiceError{
	Code:             "FES-60004",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "Invalid flow ID provided in the request",
}

// ErrorInputDataNotFound defines the error response for missing input data errors.
var ErrorInputDataNotFound = serviceerror.ServiceError{
	Code:             "FES-60005",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "One or more input data is required to execute the flow",
}

// Server error structs

// ErrorFlowGraphNotInitialized defines the error response for uninitialized flow graph errors.
var ErrorFlowGraphNotInitialized = serviceerror.ServiceError{
	Code:             "FES-65001",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Flow graph is not initialized or is nil",
}

// ErrorFlowGraphNotFound defines the error response for flow graph not found errors.
var ErrorFlowGraphNotFound = serviceerror.ServiceError{
	Code:             "FES-65002",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Flow graph not found for the graph ID",
}

// ErrorStartNodeNotFoundInGraph defines the error response for start node not found in the flow graph.
var ErrorStartNodeNotFoundInGraph = serviceerror.ServiceError{
	Code:             "FES-65003",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Start node not found in the flow graph",
}

// ErrorNodeResponseStatusNotFound defines the error response for node response status not found in the flow graph.
var ErrorNodeResponseStatusNotFound = serviceerror.ServiceError{
	Code:             "FES-65004",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Node response status not found in the flow graph",
}

// ErrorMovingToNextNode defines the error response for errors while moving to the next node in the flow graph.
var ErrorMovingToNextNode = serviceerror.ServiceError{
	Code:             "FES-65005",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while moving to the next node",
}

// ErrorResolvingStepForRedirection defines the error response for errors while resolving step for redirection.
var ErrorResolvingStepForRedirection = serviceerror.ServiceError{
	Code:             "FES-65006",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while resolving step for redirection",
}

// ErrorResolvingStepForPrompt defines the error response for errors while resolving step for prompt.
var ErrorResolvingStepForPrompt = serviceerror.ServiceError{
	Code:             "FES-65007",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while resolving step for prompt",
}

// ErrorUnsupportedNodeResponseType defines the error response for unsupported response type from the node.
var ErrorUnsupportedNodeResponseType = serviceerror.ServiceError{
	Code:             "FES-65008",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Unsupported response type returned from the node",
}

// ErrorUnsupportedNodeResponseStatus defines the error response for unsupported response status from the node.
var ErrorUnsupportedNodeResponseStatus = serviceerror.ServiceError{
	Code:             "FES-65009",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Unsupported response status returned from the node",
}

// ErrorNodeExecutorNotFound defines the error response for node executor not found errors.
var ErrorNodeExecutorNotFound = serviceerror.ServiceError{
	Code:             "FES-65010",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "An executor not found for the node",
}

// ErrorNodeExecutorExecError defines the error response for errors while executing the node executor.
var ErrorNodeExecutorExecError = serviceerror.ServiceError{
	Code:             "FES-65011",
	Type:             serviceerror.ServerErrorType,
	Error:            "Executor Execution Error",
	ErrorDescription: "Error executing the node executor",
}

// ErrorNilResponseFromExecutor defines the error response for nil response from the executor.
var ErrorNilResponseFromExecutor = serviceerror.ServiceError{
	Code:             "FES-65012",
	Type:             serviceerror.ServerErrorType,
	Error:            "Executor Response Error",
	ErrorDescription: "Received nil response from the executor",
}

// ErrorUpdatingContextInStore defines the error response for errors while updating the flow context in the store.
var ErrorUpdatingContextInStore = serviceerror.ServiceError{
	Code:             "FES-65013",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error updating flow context in the store",
}

// ErrorAuthFlowNotConfiguredForApplication defines the error response for applications without
// an authentication flow graph configured.
var ErrorAuthFlowNotConfiguredForApplication = serviceerror.ServiceError{
	Code:             "FES-65014",
	Type:             serviceerror.ServerErrorType,
	Error:            "Invalid configuration",
	ErrorDescription: "No authentication flow graph is configured for the application",
}

// ErrorInvalidAuthFlowConfiguredForApplication defines the error response for applications with an invalid
// authentication flow graph configured.
var ErrorInvalidAuthFlowConfiguredForApplication = serviceerror.ServiceError{
	Code:             "FES-65015",
	Type:             serviceerror.ServerErrorType,
	Error:            "Invalid configuration",
	ErrorDescription: "The configured flow graph is not valid for the application authentication flow",
}
