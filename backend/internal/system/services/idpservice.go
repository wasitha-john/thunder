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

	"github.com/asgardeo/thunder/internal/idp"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// IDPService is the service for identity provider management operations.
type IDPService struct {
	idpHandler *idp.IDPHandler
}

// NewIDPService creates a new instance of IDPService.
func NewIDPService(mux *http.ServeMux) ServiceInterface {
	instance := &IDPService{
		idpHandler: idp.NewIDPHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for identity provider operations.
func (s *IDPService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /identity-providers", s.idpHandler.HandleIDPPostRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("GET /identity-providers", s.idpHandler.HandleIDPListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /identity-providers",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   "GET, PUT, DELETE",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /identity-providers/{id}",
		s.idpHandler.HandleIDPGetRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /identity-providers/{id}",
		s.idpHandler.HandleIDPPutRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /identity-providers/{id}",
		s.idpHandler.HandleIDPDeleteRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /identity-providers/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts2))
}
