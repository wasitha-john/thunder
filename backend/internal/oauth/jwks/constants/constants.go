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

// Package constants defines the constants used in the JWKS service.
package constants

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// ErrorWhileRetrievingTLSConfig is returned when there is an error retrieving the TLS configuration.
var ErrorWhileRetrievingTLSConfig = &serviceerror.ServiceError{
	Code:             "JWKS-5001",
	Type:             serviceerror.ServerErrorType,
	Error:            "Error while retrieving TLS configuration.",
	ErrorDescription: "An error occurred while retrieving server TLS configurations",
}

// ErrorWhileParsingCertificate is returned when there is an error parsing the server certificate.
var ErrorWhileParsingCertificate = &serviceerror.ServiceError{
	Code:             "JWKS-5002",
	Type:             serviceerror.ServerErrorType,
	Error:            "Error while parsing certificate.",
	ErrorDescription: "An error occurred while parsing the server certificate.",
}

// ErrorNoCertificateFound is returned when no certificate is found in the TLS configuration.
var ErrorNoCertificateFound = &serviceerror.ServiceError{
	Code:             "JWKS-5003",
	Type:             serviceerror.ServerErrorType,
	Error:            "No certificate found.",
	ErrorDescription: "No certificate found in TLS config.",
}

// ErrorUnsupportedPublicKeyType is returned when the public key type is not supported for JWKS.
var ErrorUnsupportedPublicKeyType = &serviceerror.ServiceError{
	Code:             "JWKS-5004",
	Type:             serviceerror.ServerErrorType,
	Error:            "Unsupported public key type.",
	ErrorDescription: "The certificate public key type is not supported for JWKS.",
}

// ErrorWhileRetrievingCertificateKid is returned when there is an error retrieving the certificate kid.
var ErrorWhileRetrievingCertificateKid = &serviceerror.ServiceError{
	Code:             "JWKS-5005",
	Type:             serviceerror.ServerErrorType,
	Error:            "Error while retrieving certificate kid.",
	ErrorDescription: "An error occurred while retrieving the certificate Key ID (kid).",
}
