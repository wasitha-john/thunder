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

// Package googleauth provides the Google OIDC authentication executor.
package googleauth

import (
	"errors"
	"fmt"
	"slices"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/executor/oauth/model"
	"github.com/asgardeo/thunder/internal/executor/oidcauth"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	jwtutils "github.com/asgardeo/thunder/internal/system/crypto/jwt/utils"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

const loggerComponentName = "GoogleOIDCAuthExecutor"

// GoogleOIDCAuthExecutor implements the OIDC authentication executor for Google.
type GoogleOIDCAuthExecutor struct {
	*oidcauth.OIDCAuthExecutor
}

// NewGoogleOIDCAuthExecutorFromProps creates a new instance of GoogleOIDCAuthExecutor with the provided properties.
func NewGoogleOIDCAuthExecutorFromProps(execProps flowmodel.ExecutorProperties,
	oAuthProps *model.BasicOAuthExecProperties) oidcauth.OIDCAuthExecutorInterface {
	// Prepare the complete OAuth properties for Google
	compOAuthProps := &model.OAuthExecProperties{
		AuthorizationEndpoint: googleAuthorizeEndpoint,
		TokenEndpoint:         googleTokenEndpoint,
		UserInfoEndpoint:      googleUserInfoEndpoint,
		JwksEndpoint:          googleJwksEndpoint,
		ClientID:              oAuthProps.ClientID,
		ClientSecret:          oAuthProps.ClientSecret,
		RedirectURI:           oAuthProps.RedirectURI,
		Scopes:                oAuthProps.Scopes,
		AdditionalParams:      oAuthProps.AdditionalParams,
	}

	base := oidcauth.NewOIDCAuthExecutor("google_oidc_auth_executor", execProps.Name,
		[]flowmodel.InputData{}, compOAuthProps)
	exec, ok := base.(*oidcauth.OIDCAuthExecutor)
	if !ok {
		panic("failed to cast GoogleOIDCAuthExecutor to OIDCAuthExecutor")
	}
	return &GoogleOIDCAuthExecutor{
		OIDCAuthExecutor: exec,
	}
}

// NewGoogleOIDCAuthExecutor creates a new instance of GoogleOIDCAuthExecutor with the provided details.
func NewGoogleOIDCAuthExecutor(id, name, clientID, clientSecret, redirectURI string,
	scopes []string, additionalParams map[string]string) oidcauth.OIDCAuthExecutorInterface {
	// Prepare the OAuth properties for Google
	oAuthProps := &model.OAuthExecProperties{
		AuthorizationEndpoint: googleAuthorizeEndpoint,
		TokenEndpoint:         googleTokenEndpoint,
		UserInfoEndpoint:      googleUserInfoEndpoint,
		JwksEndpoint:          googleJwksEndpoint,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		RedirectURI:           redirectURI,
		Scopes:                scopes,
		AdditionalParams:      additionalParams,
	}

	base := oidcauth.NewOIDCAuthExecutor(id, name, []flowmodel.InputData{}, oAuthProps)
	exec, ok := base.(*oidcauth.OIDCAuthExecutor)
	if !ok {
		panic("failed to cast GoogleOIDCAuthExecutor to OIDCAuthExecutor")
	}
	return &GoogleOIDCAuthExecutor{
		OIDCAuthExecutor: exec,
	}
}

// Execute executes the Google OIDC authentication flow.
func (g *GoogleOIDCAuthExecutor) Execute(ctx *flowmodel.NodeContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Executing Google OIDC auth executor",
		log.String("executorID", g.GetID()), log.String("flowID", ctx.FlowID))

	execResp := &flowmodel.ExecutorResponse{}

	if g.CheckInputData(ctx, execResp) {
		logger.Debug("Required input data for Google OIDC auth executor is not provided")
		err := g.BuildAuthorizeFlow(ctx, execResp)
		if err != nil {
			return nil, err
		}

		logger.Debug("Google OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)))
	} else {
		err := g.ProcessAuthFlowResponse(ctx, execResp)
		if err != nil {
			return nil, err
		}

		logger.Debug("Google OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)),
			log.Bool("isAuthenticated", execResp.AuthenticatedUser.IsAuthenticated))
	}

	return execResp, nil
}

// ProcessAuthFlowResponse processes the response from the Google OIDC authentication flow.
func (g *GoogleOIDCAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String("executorID", g.GetID()), log.String("flowID", ctx.FlowID))
	logger.Debug("Processing Google OIDC auth flow response")

	code, okCode := ctx.UserInputData["code"]
	if okCode && code != "" {
		tokenResp, err := g.ExchangeCodeForToken(ctx, execResp, code)
		if err != nil {
			logger.Error("Failed to exchange authorization code for token", log.Error(err))
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}

		err = g.validateTokenResponse(tokenResp)
		if err != nil {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = err.Error()
			return nil
		}

		if tokenResp.Scope == "" {
			logger.Debug("Scopes are empty in the token response")
			execResp.AuthenticatedUser = authnmodel.AuthenticatedUser{
				IsAuthenticated: true,
				UserID:          "550e8400-e29b-41d4-a716-446655440000",
			}
		} else {
			authenticatedUser, err := g.getAuthenticatedUserWithAttributes(ctx, execResp, tokenResp)
			if err != nil {
				return err
			}
			if authenticatedUser == nil {
				return nil
			}
			execResp.AuthenticatedUser = *authenticatedUser
		}
	} else {
		execResp.AuthenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	if execResp.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecComplete
	} else {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Authentication failed. Authorization code not provided or invalid."
	}

	return nil
}

// ValidateIDToken validates the ID token received from Google.
func (g *GoogleOIDCAuthExecutor) ValidateIDToken(execResp *flowmodel.ExecutorResponse, idToken string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Validating ID token")

	if g.GetJWKSEndpoint() == "" {
		return fmt.Errorf("JWKS endpoint is not configured for Google OIDC executor")
	}

	// Verify the id token signature.
	signErr := jwtutils.VerifyJWTSignatureWithJWKS(idToken, g.GetJWKSEndpoint())
	if signErr != nil {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "ID token signature verification failed: " + signErr.Error()
		return nil
	}

	// Parse the JWT claims from the ID token.
	claims, err := jwtutils.ParseJWTClaims(idToken)
	if err != nil {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Failed to parse ID token claims: " + err.Error()
		return nil
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok || (iss != "accounts.google.com" && iss != "https://accounts.google.com") {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = fmt.Sprintf("Invalid issuer: %s in the id token", iss)
		return nil
	}

	// Validate audience
	aud, ok := claims["aud"].(string)
	if !ok || aud != g.GetOAuthProperties().ClientID {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = fmt.Sprintf("Invalid audience: %s in the id token", aud)
		return nil
	}

	// Validate expiration time
	exp, ok := claims["exp"].(float64)
	if !ok {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Missing expiration claim in the id token"
		return nil
	}
	if time.Now().Unix() >= int64(exp) {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "ID token has expired"
		return nil
	}

	// Check if token was issued in the future (to prevent clock skew issues)
	iat, ok := claims["iat"].(float64)
	if !ok {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Missing issued at claim in the id token"
		return nil
	}
	if time.Now().Unix() < int64(iat) {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "ID token was issued in the future"
		return nil
	}

	// Check for specific domain if configured in additional params
	if hd, found := claims["hd"]; found {
		if domain, exists := g.GetOAuthProperties().AdditionalParams["hd"]; exists && domain != "" {
			if hdStr, ok := hd.(string); !ok || hdStr != domain {
				execResp.Status = flowconst.ExecFailure
				execResp.FailureReason = fmt.Sprintf("ID token is not from the expected hosted domain: %s", domain)
				return nil
			}
		}
	}

	return nil
}

// validateTokenResponse validates the token response received from Google.
func (g *GoogleOIDCAuthExecutor) validateTokenResponse(tokenResp *model.TokenResponse) error {
	if tokenResp == nil {
		return errors.New("token response is nil")
	}
	if tokenResp.AccessToken == "" {
		return errors.New("access token is empty in the token response")
	}
	return nil
}

// getAuthenticatedUserWithAttributes retrieves the authenticated user with attributes from the token response.
func (g *GoogleOIDCAuthExecutor) getAuthenticatedUserWithAttributes(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse, tokenResp *model.TokenResponse) (*authnmodel.AuthenticatedUser, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, g.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))

	// If scopes contains openid, check if the id token is present.
	if slices.Contains(g.GetOAuthProperties().Scopes, "openid") && tokenResp.IDToken == "" {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "ID token is empty in the token response."
		return nil, nil
	}

	userClaims := make(map[string]string)
	if tokenResp.IDToken != "" {
		if err := g.ValidateIDToken(execResp, tokenResp.IDToken); err != nil {
			return nil, fmt.Errorf("failed to validate ID token: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil, nil
		}

		idTokenClaims, err := g.GetIDTokenClaims(execResp, tokenResp.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to extract ID token claims: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil, nil
		}
		if len(idTokenClaims) != 0 {
			// Validate nonce if configured.
			if nonce, ok := ctx.UserInputData["nonce"]; ok && nonce != "" {
				if idTokenClaims["nonce"] != nonce {
					execResp.Status = flowconst.ExecFailure
					execResp.FailureReason = "Nonce mismatch in ID token claims."
					return nil, nil
				}
			}

			// Filter non-user claims from the ID token claims.
			for attr, val := range idTokenClaims {
				if !slices.Contains(idTokenNonUserAttributes, attr) {
					userClaims[attr] = systemutils.ConvertInterfaceValueToString(val)
				}
			}
			logger.Debug("Extracted ID token claims", log.Any("claims", userClaims))
		}
	}

	if len(g.GetOAuthProperties().Scopes) == 0 ||
		(len(g.GetOAuthProperties().Scopes) == 1 && slices.Contains(g.GetOAuthProperties().Scopes, "openid")) {
		logger.Debug("No additional scopes configured.")
	} else {
		userInfo, err := g.GetUserInfo(ctx, execResp, tokenResp.AccessToken)
		if err != nil {
			return nil, errors.New("failed to get user info: " + err.Error())
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil, nil
		}
		for key, value := range userInfo {
			userClaims[key] = value
		}
	}

	authenticatedUser := authnmodel.AuthenticatedUser{
		IsAuthenticated: true,
		UserID:          "550e8400-e29b-41d4-a716-446655440000",
		Attributes:      userClaims,
	}

	return &authenticatedUser, nil
}
