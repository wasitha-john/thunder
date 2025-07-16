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
)

// Client error structs

// APIErrorJSONDecodeError defines the error response for json decode errors.
var APIErrorJSONDecodeError = apierror.ErrorResponse{
	Code:        "ANE-1001",
	Message:     "Invalid request payload",
	Description: "Failed to decode request payload",
}

// APIErrorInvalidRequest defines the error response for invalid requests.
var APIErrorInvalidRequest = apierror.ErrorResponse{
	Code:        "ANE-1002",
	Message:     "Invalid request",
	Description: "The request is invalid or malformed",
}

// APIErrorSessionNotFound defines the error response for session not found errors.
var APIErrorSessionNotFound = apierror.ErrorResponse{
	Code:        "ANE-1003",
	Message:     "Session not found",
	Description: "The session data could not be found for the provided data",
}

// APIErrorAppIDNotFound defines the error response for application ID not found errors.
var APIErrorAppIDNotFound = apierror.ErrorResponse{
	Code:        "ANE-1004",
	Message:     "Application ID not found",
	Description: "The application ID could not be found in the session data",
}

// APIErrorFlowExecutionError defines the error response for client-side flow execution errors.
var APIErrorFlowExecutionError = apierror.ErrorResponse{
	Code:        "ANE-1005",
	Message:     "Flow execution error",
	Description: "An error occurred while executing the authentication flow",
}

// Server error structs

// ServerErrorFlowExecutionError defines the error response for server-side flow execution errors.
var ServerErrorFlowExecutionError = apierror.ErrorResponse{
	Code:        "ANE-5001",
	Message:     "Flow execution error",
	Description: "An error occurred while executing the authentication flow",
}

// ServerErrorFlowAssertionNotFound defines the error response for flow assertion not found errors.
var ServerErrorFlowAssertionNotFound = apierror.ErrorResponse{
	Code:        "ANE-5002",
	Message:     "Flow assertion not found",
	Description: "The assertion could not be found in the flow response",
}

// ServerErrorJWTDecodeError defines the error response for JWT decode errors.
var ServerErrorJWTDecodeError = apierror.ErrorResponse{
	Code:        "ANE-5003",
	Message:     "JWT decode error",
	Description: "Failed to decode the JWT token",
}

// ServerErrorRedirectURIConstructionError defines the error response for redirect URI construction errors.
var ServerErrorRedirectURIConstructionError = apierror.ErrorResponse{
	Code:        "ANE-5004",
	Message:     "Redirect URI construction error",
	Description: "Failed to construct the redirect URI for the authentication flow",
}
