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

var APIErrorFlowRequestJSONDecodeError = apierror.ErrorResponse{
	Code:        "FES-60001",
	Message:     "Invalid request payload",
	Description: "Failed to decode request payload",
}

var ErrorNodeResponse = serviceerror.ServiceError{
	Code:             "FES-60002",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid node response",
	ErrorDescription: "Error response received from the node",
}

var ErrorInvalidAppID = serviceerror.ServiceError{
	Code:             "FES-60003",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "Invalid app ID provided in the request",
}

var ErrorInvalidFlowID = serviceerror.ServiceError{
	Code:             "FES-60004",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "Invalid flow ID provided in the request",
}

var ErrorInputDataNotFound = serviceerror.ServiceError{
	Code:             "FES-60005",
	Type:             serviceerror.ClientErrorType,
	Error:            "Invalid request",
	ErrorDescription: "One or more input data is required to execute the flow",
}

// Server error structs
var ErrorFlowGraphNotInitialized = serviceerror.ServiceError{
	Code:             "FES-65001",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Flow graph is not initialized or is nil",
}

var ErrorFlowGraphNotFound = serviceerror.ServiceError{
	Code:             "FES-65002",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Flow graph not found for the graph ID",
}

var ErrorStartNodeNotFoundInGraph = serviceerror.ServiceError{
	Code:             "FES-65003",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Start node not found in the flow graph",
}

var ErrorNodeResponseStatusNotFound = serviceerror.ServiceError{
	Code:             "FES-65004",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Node response status not found in the flow graph",
}

var ErrorMovingToNextNode = serviceerror.ServiceError{
	Code:             "FES-65005",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while moving to the next node",
}

var ErrorResolvingStepForRedirection = serviceerror.ServiceError{
	Code:             "FES-65006",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while resolving step for redirection",
}

var ErrorResolvingStepForPrompt = serviceerror.ServiceError{
	Code:             "FES-65007",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Error while resolving step for prompt",
}

var ErrorUnsupportedNodeResponseType = serviceerror.ServiceError{
	Code:             "FES-65008",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Unsupported response type returned from the node",
}

var ErrorUnsupportedNodeResponseStatus = serviceerror.ServiceError{
	Code:             "FES-65009",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "Unsupported response status returned from the node",
}

var ErrorNodeExecutorNotFound = serviceerror.ServiceError{
	Code:             "FES-65010",
	Type:             serviceerror.ServerErrorType,
	Error:            "Something went wrong",
	ErrorDescription: "An executor not found for the node",
}

var ErrorNodeExecutorExecError = serviceerror.ServiceError{
	Code:             "FES-65011",
	Type:             serviceerror.ServerErrorType,
	Error:            "Executor Execution Error",
	ErrorDescription: "Error executing the node executor",
}

var ErrorNilResponseFromExecutor = serviceerror.ServiceError{
	Code:             "FES-65012",
	Type:             serviceerror.ServerErrorType,
	Error:            "Executor Response Error",
	ErrorDescription: "Received nil response from the executor",
}
