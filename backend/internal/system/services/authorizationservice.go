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
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// AuthorizationService defines the service for handling OAuth2 authorization requests.
type AuthorizationService struct {
	authHandler authz.AuthorizeHandlerInterface
}

// NewAuthorizationService creates a new instance of AuthorizationService.
func NewAuthorizationService(mux *http.ServeMux) ServiceInterface {
	instance := &AuthorizationService{
		authHandler: authz.NewAuthorizeHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for the AuthorizationService.
func (s *AuthorizationService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}

	mux.HandleFunc(middleware.WithCORS("GET /oauth2/authorize",
		s.authHandler.HandleAuthorizeGetRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("POST /oauth2/authorize",
		s.authHandler.HandleAuthorizePostRequest, opts1))

	mux.HandleFunc(middleware.WithCORS("OPTIONS /oauth2/authorize",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts1))
}
