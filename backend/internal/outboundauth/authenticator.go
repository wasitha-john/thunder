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

// Package outboundauth provides the interfaces and implementations for outbound authenticators.
package outboundauth

import (
	"net/http"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/outboundauth/model"
)

// AuthenticatorInterface defines a common interface for authenticators.
type AuthenticatorInterface interface {
	Process(w http.ResponseWriter, r *http.Request, ctx *authnmodel.AuthenticationContext) error
	InitiateAuthenticationRequest(w http.ResponseWriter, r *http.Request, ctx *authnmodel.AuthenticationContext) error
	ProcessAuthenticationResponse(w http.ResponseWriter, r *http.Request, ctx *authnmodel.AuthenticationContext) error
	IsInitialRequest(r *http.Request, ctx *authnmodel.AuthenticationContext) bool
	GetAuthenticatorConfig() model.AuthenticatorConfig
	GetName() string
	GetFriendlyName() string
}
