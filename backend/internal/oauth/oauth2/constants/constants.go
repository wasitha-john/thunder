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
	RequestParamGrantType        = "grant_type"
	RequestParamClientID         = "client_id"
	RequestParamClientSecret     = "client_secret"
	RequestParamRedirectURI      = "redirect_uri"
	RequestParamUsername         = "username"
	RequestParamPassword         = "password"
	RequestParamScope            = "scope"
	RequestParamCode             = "code"
	RequestParamCodeVerifier     = "code_verifier"
	RequestParamRefreshToken     = "refresh_token"
	RequestParamResponseType     = "response_type"
	RequestParamState            = "state"
	RequestParamError            = "error"
	RequestParamErrorDescription = "error_description"
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

// GrantType defines a type for OAuth2 grant types.
type GrantType string

const (
	// GrantTypeAuthorizationCode represents the authorization code grant type.
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeClientCredentials represents the client credentials grant type.
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypePassword represents the resource owner password credentials grant type.
	GrantTypePassword GrantType = "password"
	// GrantTypeImplicit represents the implicit grant type.
	GrantTypeImplicit GrantType = "implicit"
	// GrantTypeRefreshToken represents the refresh token grant type.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// IsValid checks if the GrantType is valid.
func (gt GrantType) IsValid() bool {
	switch gt {
	case GrantTypeAuthorizationCode,
		GrantTypeClientCredentials,
		GrantTypePassword,
		GrantTypeImplicit,
		GrantTypeRefreshToken:
		return true
	default:
		return false
	}
}

// ResponseType defines a type for OAuth2 response types.
type ResponseType string

const (
	// ResponseTypeCode represents the authorization code response type.
	ResponseTypeCode ResponseType = "code"
	// ResponseTypeToken represents the implicit token response type.
	ResponseTypeToken ResponseType = "token"
)

// IsValid checks if the ResponseType is valid.
func (rt ResponseType) IsValid() bool {
	switch rt {
	case ResponseTypeCode:
		return true
	default:
		return false
	}
}

// TokenEndpointAuthMethod defines a type for token endpoint authentication methods.
type TokenEndpointAuthMethod string

const (
	// TokenEndpointAuthMethodClientSecretBasic represents the client secret basic authentication method.
	TokenEndpointAuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	// TokenEndpointAuthMethodClientSecretPost represents the client secret post authentication method.
	TokenEndpointAuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	// TokenEndpointAuthMethodNone represents no authentication method.
	TokenEndpointAuthMethodNone TokenEndpointAuthMethod = "none"
)

// IsValid checks if the TokenEndpointAuthMethod is valid.
func (tam TokenEndpointAuthMethod) IsValid() bool {
	switch tam {
	case TokenEndpointAuthMethodClientSecretBasic,
		TokenEndpointAuthMethodClientSecretPost,
		TokenEndpointAuthMethodNone:
		return true
	default:
		return false
	}
}

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
