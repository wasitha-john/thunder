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

// Package oidcauth provides the OIDC authentication executor for handling OIDC-based authentication flows.
package oidcauth

import (
	"errors"
	"fmt"
	"slices"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	"github.com/asgardeo/thunder/internal/executor/oauth"
	"github.com/asgardeo/thunder/internal/executor/oauth/model"
	oauthmodel "github.com/asgardeo/thunder/internal/executor/oauth/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	jwtutils "github.com/asgardeo/thunder/internal/system/crypto/jwt/utils"
	"github.com/asgardeo/thunder/internal/system/log"
	systemutils "github.com/asgardeo/thunder/internal/system/utils"
)

const loggerComponentName = "OIDCAuthExecutor"

// OIDCAuthExecutorInterface defines the interface for OIDC authentication executors.
type OIDCAuthExecutorInterface interface {
	oauth.OAuthExecutorInterface
	ValidateIDToken(execResp *flowmodel.ExecutorResponse, idToken string) error
	GetIDTokenClaims(execResp *flowmodel.ExecutorResponse, idToken string) (map[string]interface{}, error)
}

// OIDCAuthExecutor implements the OIDCAuthExecutorInterface for handling generic OIDC authentication flows.
type OIDCAuthExecutor struct {
	internal oauth.OAuthExecutorInterface
}

// NewOIDCAuthExecutor creates a new instance of OIDCAuthExecutor.
func NewOIDCAuthExecutor(id, name string, oAuthProps *oauthmodel.OAuthExecProperties) OIDCAuthExecutorInterface {
	scopes := oAuthProps.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append(scopes, "openid")
	}
	base := oauth.NewOAuthExecutor(id, name, &oauthmodel.OAuthExecProperties{
		AuthorizationEndpoint: oAuthProps.AuthorizationEndpoint,
		TokenEndpoint:         oAuthProps.TokenEndpoint,
		UserInfoEndpoint:      oAuthProps.UserInfoEndpoint,
		LogoutEndpoint:        oAuthProps.LogoutEndpoint,
		JwksEndpoint:          oAuthProps.JwksEndpoint,
		ClientID:              oAuthProps.ClientID,
		ClientSecret:          oAuthProps.ClientSecret,
		RedirectURI:           oAuthProps.RedirectURI,
		Scopes:                scopes,
		AdditionalParams:      oAuthProps.AdditionalParams,
		Properties:            oAuthProps.Properties,
	})

	return &OIDCAuthExecutor{
		internal: base,
	}
}

// GetID returns the ID of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetID() string {
	return o.internal.GetID()
}

// GetName returns the name of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetName() string {
	return o.internal.GetName()
}

// GetProperties returns the properties of the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetProperties() flowmodel.ExecutorProperties {
	return o.internal.GetProperties()
}

// GetOAuthProperties returns the OAuth properties of the executor.
func (o *OIDCAuthExecutor) GetOAuthProperties() oauthmodel.OAuthExecProperties {
	return o.internal.GetOAuthProperties()
}

// GetCallBackURL returns the callback URL for the OIDC authentication.
func (o *OIDCAuthExecutor) GetCallBackURL() string {
	return o.internal.GetCallBackURL()
}

// GetAuthorizationEndpoint returns the authorization endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetAuthorizationEndpoint() string {
	return o.internal.GetAuthorizationEndpoint()
}

// GetTokenEndpoint returns the token endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetTokenEndpoint() string {
	return o.internal.GetTokenEndpoint()
}

// GetUserInfoEndpoint returns the user info endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetUserInfoEndpoint() string {
	return o.internal.GetUserInfoEndpoint()
}

// GetLogoutEndpoint returns the logout endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetLogoutEndpoint() string {
	return o.internal.GetLogoutEndpoint()
}

// GetJWKSEndpoint returns the JWKs endpoint of the OIDC authentication.
func (o *OIDCAuthExecutor) GetJWKSEndpoint() string {
	return o.internal.GetJWKSEndpoint()
}

// Execute executes the OIDC authentication logic.
func (o *OIDCAuthExecutor) Execute(ctx *flowmodel.NodeContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing OIDC authentication executor")

	execResp := &flowmodel.ExecutorResponse{}

	// Check if the required input data is provided
	if o.requiredInputData(ctx, execResp) {
		// If required input data is not provided, return incomplete status with redirection to OIDC provider.
		logger.Debug("Required input data for OIDC authentication executor is not provided")
		err := o.BuildAuthorizeFlow(ctx, execResp)
		if err != nil {
			return nil, err
		}
	} else {
		err := o.ProcessAuthFlowResponse(ctx, execResp)
		if err != nil {
			return nil, err
		}
	}

	logger.Debug("OIDC authentication executor execution completed",
		log.String("status", string(execResp.Status)),
		log.Bool("isAuthenticated", ctx.AuthenticatedUser.IsAuthenticated))

	return execResp, nil
}

// BuildAuthorizeFlow constructs the redirection to the external OIDC provider for user authentication.
func (o *OIDCAuthExecutor) BuildAuthorizeFlow(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse) error {
	return o.internal.BuildAuthorizeFlow(ctx, execResp)
}

// ProcessAuthFlowResponse processes the response from the OIDC authentication flow and authenticates the user.
func (o *OIDCAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Processing OIDC authentication response")

	// Process authorization code if available
	code, ok := ctx.UserInputData["code"]
	if ok && code != "" {
		// Exchange authorization code for tokenResp
		tokenResp, err := o.ExchangeCodeForToken(ctx, execResp, code)
		if err != nil {
			logger.Error("Failed to exchange code for a token", log.Error(err))
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}

		// Validate the token response
		if tokenResp.AccessToken == "" {
			logger.Debug("Access token is empty in the token response")
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "Access token is empty in the token response."
			return nil
		}

		if tokenResp.Scope == "" && tokenResp.IDToken == "" {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "ID token is empty in the token response."
			return nil
		}

		userClaims := make(map[string]string)

		// Validate the id token.
		if err := o.ValidateIDToken(execResp, tokenResp.IDToken); err != nil {
			return errors.New("failed to validate ID token: " + err.Error())
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}

		// Extract claims from the id token.
		idTokenClaims, err := o.GetIDTokenClaims(execResp, tokenResp.IDToken)
		if err != nil {
			return errors.New("failed to extract ID token claims: " + err.Error())
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}
		if len(idTokenClaims) != 0 {
			// Filter non-user claims from the ID token claims.
			for attr, val := range idTokenClaims {
				if !slices.Contains(idTokenNonUserAttributes, attr) {
					userClaims[attr] = systemutils.ConvertInterfaceValueToString(val)
				}
			}
			logger.Debug("Extracted ID token claims", log.Any("claims", userClaims))
		}

		if len(o.GetOAuthProperties().Scopes) == 1 && slices.Contains(o.GetOAuthProperties().Scopes, "openid") {
			logger.Debug("No additional scopes configured.")
		} else {
			// Get user info using the access token
			userInfo, err := o.GetUserInfo(ctx, execResp, tokenResp.AccessToken)
			if err != nil {
				return errors.New("failed to get user info: " + err.Error())
			}
			if execResp.Status == flowconst.ExecFailure {
				return nil
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
			Domain:                 o.GetName(),
			AuthenticatedSubjectID: username,
			Attributes:             userClaims,
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
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Authentication failed. Authorization code not provided or invalid."
	}

	return nil
}

// requiredInputData adds the required input data for the OIDC authentication flow to the executor response.
// Returns true if input data should be requested from the user.
func (o *OIDCAuthExecutor) requiredInputData(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse) bool {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()), log.String(log.LoggerKeyFlowID, ctx.FlowID))

	// Check if the authorization code is already provided
	if code, ok := ctx.UserInputData["code"]; ok && code != "" {
		return false
	}

	// Define the authenticator specific required input data.
	gitReqData := []flowmodel.InputData{
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
		logger.Debug("No required input data defined for OIDC authentication executor")
		// If no required input data is defined, use the default required data.
		requiredData = gitReqData
	} else {
		// Append the default required data if not already present.
		for _, inputData := range gitReqData {
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
			logger.Debug("Required input data not provided by user",
				log.String("inputDataName", inputData.Name))
		}
	}

	return requireData
}

// ExchangeCodeForToken exchanges the authorization code for an access token.
func (o *OIDCAuthExecutor) ExchangeCodeForToken(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	code string) (*model.TokenResponse, error) {
	return o.internal.ExchangeCodeForToken(ctx, execResp, code)
}

// GetUserInfo fetches user information from the OAuth provider using the access token.
func (o *OIDCAuthExecutor) GetUserInfo(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	accessToken string) (map[string]string, error) {
	return o.internal.GetUserInfo(ctx, execResp, accessToken)
}

// ValidateIDToken validates the ID token.
func (o *OIDCAuthExecutor) ValidateIDToken(execResp *flowmodel.ExecutorResponse, idToken string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Validating ID token")

	// Verify the id token signature.
	if o.GetJWKSEndpoint() != "" {
		signErr := jwtutils.VerifyJWTSignatureWithJWKS(idToken, o.GetJWKSEndpoint())
		if signErr != nil {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "ID token signature verification failed: " + signErr.Error()
		}
	}

	return nil
}

// GetIDTokenClaims extracts the ID token claims from the provided ID token.
func (o *OIDCAuthExecutor) GetIDTokenClaims(execResp *flowmodel.ExecutorResponse,
	idToken string) (map[string]interface{}, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Extracting claims from the ID token")

	claims, err := jwtutils.ParseJWTClaims(idToken)
	if err != nil {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Failed to parse ID token claims: " + err.Error()
	}

	logger.Debug("ID token claims extracted successfully", log.Any("numClaims", len(claims)))
	return claims, nil
}
