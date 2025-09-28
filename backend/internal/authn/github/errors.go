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

package github

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// Server errors for GitHub OAuth authentication.
var (
	// ErrorUnexpectedServerError is the error returned when an unexpected error occurs while processing the request.
	ErrorUnexpectedServerError = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTH-GITHUB-5000",
		Error:            "Something went wrong",
		ErrorDescription: "An unexpected error occurred while processing the request",
	}
	// ErrorFetchingUserEmails is the error returned when there is an error fetching user emails from GitHub.
	ErrorFetchingUserEmails = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTH-GITHUB-5001",
		Error:            "Error fetching user emails",
		ErrorDescription: "An error occurred while fetching user emails from GitHub",
	}
)
