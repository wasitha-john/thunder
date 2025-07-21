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

// Package constants defines constants used across the OAuth2 module.
package constants

// OAuth2 request parameters.
const (
	GrantType        = "grant_type"
	ClientID         = "client_id"
	ClientSecret     = "client_secret"
	RedirectURI      = "redirect_uri"
	Username         = "username"
	Password         = "password"
	Scope            = "scope"
	Code             = "code"
	CodeVerifier     = "code_verifier"
	RefreshToken     = "refresh_token"
	ResponseType     = "response_type"
	State            = "state"
	Error            = "error"
	ErrorDescription = "error_description"
)

// Server OAuth constants.
const (
	SessionDataKey        = "sessionDataKey"
	SessionDataKeyConsent = "sessionDataKeyConsent"
	ShowInsecureWarning   = "showInsecureWarning"
	AppID                 = "applicationId"
	Assertion             = "assertion"
)

// Oauth message types.
const (
	TypeInitialAuthorizationRequest     = "initialAuthorizationRequest"
	TypeAuthorizationResponseFromEngine = "authorizationResponseFromEngine"
	TypeConsentResponseFromUser         = "consentResponseFromUser"
)

// OAuth2 endpoints.
const (
	OAuth2TokenEndpoint         = "/oauth2/token" // #nosec G101
	OAuth2AuthorizationEndpoint = "/oauth2/authorize"
	OAuth2IntrospectionEndpoint = "/oauth2/introspect"
	OAuth2RevokeEndpoint        = "/oauth2/revoke"
	OAuth2UserInfoEndpoint      = "/oauth2/userinfo"
	OAuth2JWKSEndpoint          = "/oauth2/jwks"
	OAuth2LogoutEndpoint        = "/oauth2/logout"
)

// OAuth2 grant types.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypePassword          = "password"
	GrantTypeImplicit          = "implicit"
	GrantTypeRefreshToken      = "refresh_token"
)

// OAuth2 response types.
const (
	ResponseTypeCode = "code"
)

// OAuth2 token types.
const (
	TokenTypeBearer = "Bearer"
)

// OAuth2 error codes.
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorAccessDenied            = "access_denied"
)
