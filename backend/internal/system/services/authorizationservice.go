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

package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/oauth/oauth2/authz"
	"github.com/asgardeo/thunder/internal/system/server"
)

// AuthorizationService defines the service for handling OAuth2 authorization requests.
type AuthorizationService struct {
	ServerOpsService server.ServerOperationServiceInterface
	authHandler      authz.AuthorizeHandlerInterface
}

// NewAuthorizationService creates a new instance of AuthorizationService.
func NewAuthorizationService(mux *http.ServeMux) ServiceInterface {
	instance := &AuthorizationService{
		ServerOpsService: server.NewServerOperationService(),
		authHandler:      authz.NewAuthorizeHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for the AuthorizationService.
func (s *AuthorizationService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}

	s.ServerOpsService.WrapHandleFunction(mux, "GET /oauth2/authorize", &opts1,
		s.authHandler.HandleAuthorizeGetRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "POST /oauth2/authorize", &opts1,
		s.authHandler.HandleAuthorizePostRequest)

	s.ServerOpsService.WrapHandleFunction(mux, "OPTIONS /oauth2/authorize", &opts1,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
}
