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
	"fmt"
	"slices"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/executor/oidcauth"
	"github.com/asgardeo/thunder/internal/executor/oidcauth/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	jwtutils "github.com/asgardeo/thunder/internal/system/crypto/jwt/utils"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

const loggerComponentName = "GoogleAuthExecutor"

// GoogleOIDCAuthExecutor implements the OIDC authentication executor for Google.
type GoogleOIDCAuthExecutor struct {
	*oidcauth.OIDCAuthExecutor
}

// NewGoogleOIDCAuthExecutorFromProps creates a new instance of GoogleOIDCAuthExecutor with the provided properties.
func NewGoogleOIDCAuthExecutorFromProps(execProps flowmodel.ExecutorProperties,
	oidcProps *model.BasicOIDCExecProperties) oidcauth.OIDCAuthExecutorInterface {
	// Prepare the complete OIDC properties for Google
	compOIDCProps := &model.OIDCExecProperties{
		AuthorizationEndpoint: googleAuthorizeEndpoint,
		TokenEndpoint:         googleTokenEndpoint,
		UserInfoEndpoint:      googleUserInfoEndpoint,
		JwksEndpoint:          googleJwksEndpoint,
		ClientID:              oidcProps.ClientID,
		ClientSecret:          oidcProps.ClientSecret,
		RedirectURI:           oidcProps.RedirectURI,
		Scopes:                oidcProps.Scopes,
		AdditionalParams:      oidcProps.AdditionalParams,
	}

	base := oidcauth.NewOIDCAuthExecutor("google_oidc_auth_executor", execProps.Name, compOIDCProps)

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
	// Prepare the OIDC properties for Google
	oidcProps := &model.OIDCExecProperties{
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

	base := oidcauth.NewOIDCAuthExecutor(id, name, oidcProps)

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

	execResp := &flowmodel.ExecutorResponse{
		Status: flowconst.ExecIncomplete,
	}

	// Check if the required input data is provided
	if g.requiredInputData(ctx, execResp) {
		// If required input data is not provided, return incomplete status with redirection to Google.
		logger.Debug("Required input data for Google OIDC auth executor is not provided")

		g.BuildAuthorizeFlow(ctx, execResp)

		logger.Debug("Google OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)))
	} else {
		g.ProcessAuthFlowResponse(ctx, execResp)

		logger.Debug("Google OIDC auth executor execution completed",
			log.String("status", string(execResp.Status)),
			log.Bool("isAuthenticated", ctx.AuthenticatedUser.IsAuthenticated))
	}

	return execResp, nil
}

// ProcessAuthFlowResponse processes the response from the Google OIDC authentication flow.
func (g *GoogleOIDCAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String("executorID", g.GetID()), log.String("flowID", ctx.FlowID))
	logger.Debug("Processing Google OIDC auth flow response")

	execResp.Status = flowconst.ExecIncomplete

	// Process authorization code if available
	code, okCode := ctx.UserInputData["code"]
	if okCode && code != "" {
		// Exchange authorization code for tokenResp
		tokenResp, err := g.ExchangeCodeForToken(ctx, code)
		if err != nil {
			logger.Error("Failed to exchange code for a token", log.Error(err))
			execResp.Status = flowconst.ExecError
			execResp.Error = "Failed to authenticate with OIDC provider: " + err.Error()
			return
		}

		// Validate the token response
		if tokenResp.AccessToken == "" {
			logger.Debug("Access token is empty in the token response")
			execResp.Status = flowconst.ExecUserError
			execResp.Error = "Access token is empty in the token response. Please provide a valid authorization code."
			return
		}

		if tokenResp.Scope == "" {
			logger.Debug("Scopes are empty in the token response")
			ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
				IsAuthenticated:        true,
				UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Username:               "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Domain:                 g.GetName(),
				AuthenticatedSubjectID: "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
			}
		} else {
			// If scopes contains openid, check if the id token is present.
			if slices.Contains(g.GetOIDCProperties().Scopes, "openid") && tokenResp.IDToken == "" {
				logger.Debug("ID token is empty in the token response")
				execResp.Status = flowconst.ExecUserError
				execResp.Error = "ID token is empty in the token response. Please provide a valid authorization code."
				return
			}

			userClaims := make(map[string]string)

			if tokenResp.IDToken != "" {
				// Validate the id token.
				if err := g.ValidateIDToken(tokenResp.IDToken); err != nil {
					execResp.Status = flowconst.ExecUserError
					execResp.Error = "ID token validation failed: " + err.Error()
					return
				}

				// Extract claims from the id token.
				idTokenClaims, err := g.GetIDTokenClaims(tokenResp.IDToken)
				if err != nil {
					logger.Error("Failed to extract ID token claims", log.Error(err))
					execResp.Status = flowconst.ExecUserError
					execResp.Error = "Failed to extract ID token claims: " + err.Error()
					return
				}
				if len(idTokenClaims) != 0 {
					// Validate nonce if configured.
					if nonce, ok := ctx.UserInputData["nonce"]; ok && nonce != "" {
						if idTokenClaims["nonce"] != nonce {
							logger.Debug("Nonce mismatch in ID token claims",
								log.String("expectedNonce", nonce),
								log.String("idTokenNonce", idTokenClaims["nonce"].(string)))
							execResp.Status = flowconst.ExecUserError
							execResp.Error = "Nonce mismatch in ID token claims."
							return
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

			if len(g.GetOIDCProperties().Scopes) == 0 ||
				(len(g.GetOIDCProperties().Scopes) == 1 && slices.Contains(g.GetOIDCProperties().Scopes, "openid")) {
				logger.Debug("No additional scopes configured.")
			} else {
				// Get user info using the access token
				userInfo, err := g.GetUserInfo(ctx, tokenResp.AccessToken)
				if err != nil {
					logger.Error("Failed to get user info", log.Error(err))
					execResp.Status = flowconst.ExecUserError
					execResp.Error = "Failed to get user information: " + err.Error()
					return
				}
				for key, value := range userInfo {
					userClaims[key] = value
				}
			}

			// Determine username from the user claims.
			username := ""
			if sub, ok := userClaims["sub"]; ok {
				username = sub
				delete(userClaims, "sub")
			}
			if email, ok := userClaims["email"]; ok && email != "" {
				username = email
			}

			ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
				IsAuthenticated:        true,
				UserID:                 "143e87c1-ccfc-440d-b0a5-bb23c9a2f39e",
				Username:               username,
				Domain:                 g.GetName(),
				AuthenticatedSubjectID: username,
				Attributes:             userClaims,
			}
		}
	} else {
		// Fail the authentication if the authorization code is not provided
		ctx.AuthenticatedUser = authnmodel.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	// Set the flow response status based on the authentication result.
	if ctx.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecComplete
	} else {
		execResp.Status = flowconst.ExecUserError
		execResp.Type = flowconst.ExecRedirection
		execResp.Error = "User is not authenticated. Please provide a valid authorization code."
	}
}

// requiredInputData adds the required input data for the Google OIDC authentication flow.
// Returns true if input data should be requested from the user.
func (g *GoogleOIDCAuthExecutor) requiredInputData(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) bool {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	// Check if the authorization code is already provided
	if code, ok := ctx.UserInputData["code"]; ok && code != "" {
		return false
	}

	// Define the authenticator specific required input data.
	googleReqData := []flowmodel.InputData{
		{
			Name:     "code",
			Type:     "string",
			Required: true,
		},
	}

	// Check for the required input data. Also appends the authenticator specific input data.
	// TODO: This validation should be moved to the flow composer. Ideally the validation and appending
	//  should happen during the flow definition creation.
	requiredData := ctx.NodeInputData
	if len(requiredData) == 0 {
		logger.Debug("No required input data defined for Google OIDC auth executor")
		// If no required input data is defined, use the default required data.
		requiredData = googleReqData
	} else {
		// Append the default required data if not already present.
		for _, inputData := range googleReqData {
			exists := false
			for _, existingInputData := range requiredData {
				if existingInputData.Name == inputData.Name {
					exists = true
					break
				}
			}
			// If the input data already exists, skip adding it again.
			if !exists {
				requiredData = append(requiredData, inputData)
			}
		}
	}

	requireData := false

	if execResp.RequiredData == nil {
		execResp.RequiredData = make([]flowmodel.InputData, 0)
	}

	if len(ctx.UserInputData) == 0 {
		execResp.RequiredData = append(execResp.RequiredData, requiredData...)
		return true
	}

	// Check if the required input data is provided by the user.
	for _, inputData := range requiredData {
		if _, ok := ctx.UserInputData[inputData.Name]; !ok {
			if !inputData.Required {
				logger.Debug("Skipping optional input data that is not provided by user",
					log.String("inputDataName", inputData.Name))
				continue
			}
			execResp.RequiredData = append(execResp.RequiredData, inputData)
			requireData = true
			logger.Debug("Required input data not provided by user", log.String("inputDataName", inputData.Name))
		}
	}

	return requireData
}

// ValidateIDToken validates the ID token received from Google.
func (g *GoogleOIDCAuthExecutor) ValidateIDToken(idToken string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Validating ID token")

	if g.GetJWKSEndpoint() == "" {
		return fmt.Errorf("JWKS endpoint is not configured for Google OIDC executor")
	}

	// Verify the id token signature.
	signErr := jwtutils.VerifyJWTSignatureWithJWKS(idToken, g.GetJWKSEndpoint())
	if signErr != nil {
		return fmt.Errorf("ID token signature verification failed: %w", signErr)
	}

	// Parse the JWT claims from the ID token.
	claims, err := jwtutils.ParseJWTClaims(idToken)
	if err != nil {
		return fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok || (iss != "accounts.google.com" && iss != "https://accounts.google.com") {
		return fmt.Errorf("invalid issuer: %s", iss)
	}

	// Validate audience
	aud, ok := claims["aud"].(string)
	if !ok || aud != g.GetOIDCProperties().ClientID {
		return fmt.Errorf("invalid audience: %s", aud)
	}

	// Validate expiration time
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing expiration claim")
	}
	if time.Now().Unix() >= int64(exp) {
		return fmt.Errorf("token has expired")
	}

	// Check if token was issued in the future (to prevent clock skew issues)
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing issued at claim")
	}
	if time.Now().Unix() < int64(iat) {
		return fmt.Errorf("token was issued in the future")
	}

	// Check for specific domain if configured in additional params
	if hd, found := claims["hd"]; found {
		if domain, exists := g.GetOIDCProperties().AdditionalParams["hd"]; exists && domain != "" {
			if hdStr, ok := hd.(string); !ok || hdStr != domain {
				return fmt.Errorf("token is not from the expected hosted domain")
			}
		}
	}

	return nil
}
