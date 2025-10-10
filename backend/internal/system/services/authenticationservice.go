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

	"github.com/asgardeo/thunder/internal/authn"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// AuthenticationService defines the service for handling authentication-related requests.
type AuthenticationService struct {
	authHandler *authn.AuthenticationHandler
}

// NewAuthenticationService creates a new instance of AuthenticationService.
func NewAuthenticationService(mux *http.ServeMux) ServiceInterface {
	instance := &AuthenticationService{
		authHandler: authn.NewAuthenticationHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for the AuthenticationService.
func (s *AuthenticationService) RegisterRoutes(mux *http.ServeMux) {
	opts := middleware.CORSOptions{
		AllowedMethods:   "POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}

	// Credentials authentication route
	mux.HandleFunc(middleware.WithCORS("POST /auth/credentials/authenticate",
		s.authHandler.HandleCredentialsAuthRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/credentials/authenticate",
		optionsNoContentHandler, opts))

	// SMS OTP routes
	mux.HandleFunc(middleware.WithCORS("POST /auth/otp/sms/send",
		s.authHandler.HandleSendSMSOTPRequest, opts))
	mux.HandleFunc(middleware.WithCORS("POST /auth/otp/sms/verify",
		s.authHandler.HandleVerifySMSOTPRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/otp/sms/send",
		optionsNoContentHandler, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/otp/sms/verify",
		optionsNoContentHandler, opts))

	// Google OAuth routes
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/google/start",
		s.authHandler.HandleGoogleAuthStartRequest, opts))
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/google/finish",
		s.authHandler.HandleGoogleAuthFinishRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/google/start",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/google/finish",
		optionsNoContentHandler, opts))

	// GitHub OAuth routes
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/github/start",
		s.authHandler.HandleGithubAuthStartRequest, opts))
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/github/finish",
		s.authHandler.HandleGithubAuthFinishRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/github/start",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/github/finish",
		optionsNoContentHandler, opts))

	// Standard OAuth routes
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/standard/start",
		s.authHandler.HandleStandardOAuthStartRequest, opts))
	mux.HandleFunc(middleware.WithCORS("POST /auth/oauth/standard/finish",
		s.authHandler.HandleStandardOAuthFinishRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/standard/start",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /auth/oauth/standard/finish",
		optionsNoContentHandler, opts))
}

// optionsNoContentHandler handles OPTIONS requests by responding with 204 No Content.
func optionsNoContentHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
