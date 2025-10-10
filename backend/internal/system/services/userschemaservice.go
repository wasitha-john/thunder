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

// Package services handles the registration of routes and services for the system.
//
//nolint:dupl // Ignoring false positive duplicate code
package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/system/middleware"
	"github.com/asgardeo/thunder/internal/userschema/handler"
)

// UserSchemaService is the service for user schema management operations.
type UserSchemaService struct {
	userSchemaHandler *handler.UserSchemaHandler
}

// NewUserSchemaService creates a new instance of UserSchemaService.
func NewUserSchemaService(mux *http.ServeMux) ServiceInterface {
	instance := &UserSchemaService{
		userSchemaHandler: handler.NewUserSchemaHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for user schema management operations.
func (s *UserSchemaService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /user-schemas",
		s.userSchemaHandler.HandleUserSchemaPostRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("GET /user-schemas",
		s.userSchemaHandler.HandleUserSchemaListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /user-schemas",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   "GET, PUT, DELETE",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /user-schemas/{id}",
		s.userSchemaHandler.HandleUserSchemaGetRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /user-schemas/{id}",
		s.userSchemaHandler.HandleUserSchemaPutRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /user-schemas/{id}",
		s.userSchemaHandler.HandleUserSchemaDeleteRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /user-schemas/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts2))
}
