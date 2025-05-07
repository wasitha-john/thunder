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

package constants

// OAuth2 request parameters.
const (
	GRANT_TYPE        = "grant_type"
	CLIENT_ID         = "client_id"
	CLIENT_SECRET     = "client_secret"
	REDIRECT_URI      = "redirect_uri"
	USERNAME          = "username"
	PASSWORD          = "password"
	SCOPE             = "scope"
	CODE              = "code"
	CODE_VERIFIER     = "code_verifier"
	REFRESH_TOKEN     = "refresh_token"
	RESPONSE_TYPE     = "response_type"
	STATE             = "state"
	ERROR             = "error"
	ERROR_DESCRIPTION = "error_description"
)

// Server OAuth constants.
const (
	SESSION_DATA_KEY         = "sessionDataKey"
	SESSION_DATA_KEY_CONSENT = "sessionDataKeyConsent"

	OAUTH_ERROR_CODE    = "oauthErrorCode"
	OAUTH_ERROR_MESSAGE = "oauthErrorMsg"

	AUTH_ERROR_CODE    = "AuthErrorCode"
	AUTH_ERROR_MESSAGE = "AuthErrorMsg"
)

// Oauth message types.
const (
	TYPE_INITIAL_AUTHORIZATION_REQUEST         = "initialAuthorizationRequest"
	TYPE_AUTHORIZATION_RESPONSE_FROM_FRAMEWORK = "authorizationResponseFromFramework"
	TYPE_CONSENT_RESPONSE_FROM_USER            = "consentResponseFromUser"
)

// OAuth2 endpoints.
const (
	OAUTH2_TOKEN_ENDPOINT         = "/oauth2/token"
	OAUTH2_AUTHORIZATION_ENDPOINT = "/oauth2/authorize"
	OAUTH2_INTROSPECT_ENDPOINT    = "/oauth2/introspect"
	OAUTH2_REVOKE_ENDPOINT        = "/oauth2/revoke"
	OAUTH2_USERINFO_ENDPOINT      = "/oauth2/userinfo"
	OAUTH2_JWKS_URI               = "/oauth2/jwks"
	OAUTH2_LOGOUT_ENDPOINT        = "/oauth2/logout"
)

// OAuth2 grant types.
const (
	GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
	GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
	GRANT_TYPE_PASSWORD           = "password"
	GRANT_TYPE_IMPLICIT           = "implicit"
	GRANT_TYPE_REFRESH_TOKEN      = "refresh_token"
)

// OAuth2 response types.
const (
	RESPONSE_TYPE_CODE = "code"
)

// OAuth2 token types.
const (
	TOKEN_TYPE_BEARER = "Bearer"
)

// OAuth2 error codes.
const (
	ERROR_INVALID_REQUEST           = "invalid_request"
	ERROR_INVALID_CLIENT            = "invalid_client"
	ERROR_INVALID_GRANT             = "invalid_grant"
	ERROR_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	ERROR_UNSUPPORTED_GRANT_TYPE    = "unsupported_grant_type"
	ERROR_INVALID_SCOPE             = "invalid_scope"
	ERROR_SERVER_ERROR              = "server_error"
	ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	ERROR_ACCESS_DENIED             = "access_denied"
)
