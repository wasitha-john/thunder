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

package constants

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// Client errors for the certificate service.
var (
	// ErrorInvalidCertificateID is the error for an invalid certificate ID.
	ErrorInvalidCertificateID = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1001",
		Error:            "Invalid certificate ID",
		ErrorDescription: "The provided certificate ID is invalid",
	}
	// ErrorInvalidReferenceType is the error for an invalid certificate reference type.
	ErrorInvalidReferenceType = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1002",
		Error:            "Invalid certificate reference type",
		ErrorDescription: "The provided certificate reference type is invalid",
	}
	// ErrorInvalidReferenceID is the error for an invalid certificate reference ID.
	ErrorInvalidReferenceID = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1003",
		Error:            "Invalid certificate reference ID",
		ErrorDescription: "The provided certificate reference ID is invalid",
	}
	// ErrorInvalidCertificateType is the error for an invalid certificate type.
	ErrorInvalidCertificateType = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1004",
		Error:            "Invalid certificate type",
		ErrorDescription: "The provided certificate type is invalid",
	}
	// ErrorInvalidCertificateValue is the error for an invalid certificate value.
	ErrorInvalidCertificateValue = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1005",
		Error:            "Invalid certificate value",
		ErrorDescription: "The provided certificate value is invalid",
	}
	// ErrorCertificateNotFound is the error when a certificate is not found.
	ErrorCertificateNotFound = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1006",
		Error:            "Certificate not found",
		ErrorDescription: "The requested certificate could not be found",
	}
	// ErrorCertificateAlreadyExists is the error when a certificate already exists.
	ErrorCertificateAlreadyExists = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1007",
		Error:            "Certificate already exists",
		ErrorDescription: "A certificate with the same reference type and ID already exists",
	}
	// ErrorReferenceUpdateIsNotAllowed is the error when trying to update a certificate's reference type or ID.
	ErrorReferenceUpdateIsNotAllowed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "CES-1008",
		Error:            "Reference update is not allowed",
		ErrorDescription: "Updating the reference type or ID of an existing certificate is not allowed",
	}
)

// Server errors for the certificate service.
var (
	// ErrorInternalServerError is the error for an internal server error.
	ErrorInternalServerError = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "CES-5001",
		Error:            "Internal server error",
		ErrorDescription: "An unexpected error occurred while processing the request",
	}
)
