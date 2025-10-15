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

// Package oidcauth provides the OIDC authentication executor for handling OIDC-based authentication flows.
package oidcauth

import (
	"errors"
	"fmt"
	"slices"

	authncm "github.com/asgardeo/thunder/internal/authn/common"
	authnoauth "github.com/asgardeo/thunder/internal/authn/oauth"
	authnoidc "github.com/asgardeo/thunder/internal/authn/oidc"
	"github.com/asgardeo/thunder/internal/executor/identify"
	"github.com/asgardeo/thunder/internal/executor/oauth"
	"github.com/asgardeo/thunder/internal/executor/oauth/model"
	oauthmodel "github.com/asgardeo/thunder/internal/executor/oauth/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/common/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/common/model"
	"github.com/asgardeo/thunder/internal/idp"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	httpservice "github.com/asgardeo/thunder/internal/system/http"
	"github.com/asgardeo/thunder/internal/system/log"
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
	*identify.IdentifyingExecutor
	internal    oauth.OAuthExecutorInterface
	authService authnoidc.OIDCAuthnServiceInterface
}

var _ flowmodel.ExecutorInterface = (*OIDCAuthExecutor)(nil)

// NewOIDCAuthExecutor creates a new instance of OIDCAuthExecutor.
func NewOIDCAuthExecutor(id, name string, defaultInputs []flowmodel.InputData, properties map[string]string,
	oAuthProps *oauthmodel.OAuthExecProperties) OIDCAuthExecutorInterface {
	scopes := oAuthProps.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append(scopes, "openid")
	}
	compOAuthProps := oauthmodel.OAuthExecProperties{
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
	}
	base := oauth.NewOAuthExecutor(id, name, defaultInputs, properties, &compOAuthProps)

	endpoints := authnoauth.OAuthEndpoints{
		AuthorizationEndpoint: oAuthProps.AuthorizationEndpoint,
		TokenEndpoint:         oAuthProps.TokenEndpoint,
		UserInfoEndpoint:      oAuthProps.UserInfoEndpoint,
		LogoutEndpoint:        oAuthProps.LogoutEndpoint,
		JwksEndpoint:          oAuthProps.JwksEndpoint,
	}
	oAuthSvc := authnoauth.NewOAuthAuthnService(
		httpservice.NewHTTPClientWithTimeout(flowconst.DefaultHTTPTimeout),
		idp.NewIDPService(),
		endpoints,
	)
	authSvc := authnoidc.NewOIDCAuthnService(oAuthSvc, nil)

	return &OIDCAuthExecutor{
		IdentifyingExecutor: identify.NewIdentifyingExecutor(id, name, properties),
		internal:            base,
		authService:         authSvc,
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

	execResp := &flowmodel.ExecutorResponse{
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}

	// Check if the required input data is provided
	if o.CheckInputData(ctx, execResp) {
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
		log.Bool("isAuthenticated", execResp.AuthenticatedUser.IsAuthenticated))

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

	code, ok := ctx.UserInputData["code"]
	if ok && code != "" {
		tokenResp, err := o.ExchangeCodeForToken(ctx, execResp, code)
		if err != nil {
			logger.Error("Failed to exchange code for a token", log.Error(err))
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}

		idTokenClaims, err := o.GetIDTokenClaims(execResp, tokenResp.IDToken)
		if err != nil {
			return errors.New("failed to extract ID token claims: " + err.Error())
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil
		}

		// Validate nonce if configured.
		if nonce, ok := ctx.UserInputData["nonce"]; ok && nonce != "" {
			if idTokenClaims["nonce"] != nonce {
				execResp.Status = flowconst.ExecFailure
				execResp.FailureReason = "Nonce mismatch in ID token claims."
				return nil
			}
		}

		// Resolve user with the sub claim.
		// TODO: For now assume `sub` is the unique identifier for the user always.
		userID := ""
		sub, ok := idTokenClaims["sub"]
		if ok && sub != "" {
			if subStr, ok := sub.(string); ok && subStr != "" {
				userID, err = o.resolveUser(subStr, ctx, execResp)
				if err != nil {
					return err
				}
				if execResp.Status == flowconst.ExecFailure {
					return nil
				}
			}
		}

		authenticatedUser, err := o.getAuthenticatedUserWithAttributes(ctx, execResp,
			tokenResp.AccessToken, idTokenClaims, userID)
		if err != nil {
			return err
		}
		if execResp.Status == flowconst.ExecFailure || authenticatedUser == nil {
			return nil
		}
		execResp.AuthenticatedUser = *authenticatedUser
	} else {
		execResp.AuthenticatedUser = authncm.AuthenticatedUser{
			IsAuthenticated: false,
		}
	}

	if execResp.AuthenticatedUser.IsAuthenticated {
		execResp.Status = flowconst.ExecComplete
	} else if ctx.FlowType != flowconst.FlowTypeRegistration {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Authentication failed. Authorization code not provided or invalid."
	}

	return nil
}

// GetDefaultExecutorInputs returns the default required input data for the OAuthExecutor.
func (o *OIDCAuthExecutor) GetDefaultExecutorInputs() []flowmodel.InputData {
	return o.internal.GetDefaultExecutorInputs()
}

// CheckInputData checks if the required input data is provided in the context.
func (o *OIDCAuthExecutor) CheckInputData(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse) bool {
	return o.internal.CheckInputData(ctx, execResp)
}

// GetPrerequisites returns the prerequisites for the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetPrerequisites() []flowmodel.InputData {
	return o.internal.GetPrerequisites()
}

// ValidatePrerequisites validates whether the prerequisites for the OIDCAuthExecutor are met.
func (o *OIDCAuthExecutor) ValidatePrerequisites(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) bool {
	return o.internal.ValidatePrerequisites(ctx, execResp)
}

// GetUserIDFromContext retrieves the user ID from the context.
func (o *OIDCAuthExecutor) GetUserIDFromContext(ctx *flowmodel.NodeContext) (string, error) {
	return o.internal.GetUserIDFromContext(ctx)
}

// GetRequiredData returns the required input data for the OIDCAuthExecutor.
func (o *OIDCAuthExecutor) GetRequiredData(ctx *flowmodel.NodeContext) []flowmodel.InputData {
	return o.internal.GetRequiredData(ctx)
}

// ExchangeCodeForToken exchanges the authorization code for an access token.
func (o *OIDCAuthExecutor) ExchangeCodeForToken(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	code string) (*model.TokenResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Exchanging authorization code for a token", log.String("tokenEndpoint", o.GetTokenEndpoint()))

	tokenResp, svcErr := o.authService.ExchangeCodeForToken(o.GetID(), code, true)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ClientErrorType {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = svcErr.ErrorDescription
			return nil, nil
		}

		logger.Error("Failed to exchange code for a token", log.String("errorCode", svcErr.Code),
			log.String("errorDescription", svcErr.ErrorDescription))
		return nil, errors.New("failed to exchange code for token")
	}

	return &model.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo fetches user information from the OAuth provider using the access token.
func (o *OIDCAuthExecutor) GetUserInfo(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	accessToken string) (map[string]string, error) {
	return o.internal.GetUserInfo(ctx, execResp, accessToken)
}

// ValidateIDToken validates the ID token. ExchangeCodeForToken method already validates the ID token.
// Hence generally you don't need to call this method explicitly.
func (o *OIDCAuthExecutor) ValidateIDToken(execResp *flowmodel.ExecutorResponse, idToken string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Validating the ID token")

	svcErr := o.authService.ValidateIDToken(o.GetID(), idToken)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ClientErrorType {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = svcErr.ErrorDescription
			return nil
		}

		logger.Error("Failed to validate ID token", log.String("errorCode", svcErr.Code),
			log.String("errorDescription", svcErr.ErrorDescription))
		return errors.New("failed to validate ID token")
	}

	return nil
}

// GetIDTokenClaims extracts the ID token claims from the provided ID token.
func (o *OIDCAuthExecutor) GetIDTokenClaims(execResp *flowmodel.ExecutorResponse,
	idToken string) (map[string]interface{}, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Extracting claims from the ID token")

	claims, svcErr := o.authService.GetIDTokenClaims(idToken)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ClientErrorType {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = svcErr.ErrorDescription
			return nil, nil
		}

		logger.Error("Failed to extract claims from the ID token", log.String("errorCode", svcErr.Code),
			log.String("errorDescription", svcErr.ErrorDescription))
		return nil, errors.New("failed to extract claims from the ID token")
	}

	return claims, nil
}

// getAuthenticatedUserWithAttributes constructs the authenticated user object with attributes from the
// ID token and user info.
func (o *OIDCAuthExecutor) getAuthenticatedUserWithAttributes(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse, accessToken string, idTokenClaims map[string]interface{},
	userID string) (*authncm.AuthenticatedUser, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))

	userClaims := make(map[string]interface{})
	if len(idTokenClaims) != 0 {
		// Filter non-user claims from the ID token claims.
		for attr, val := range idTokenClaims {
			if !slices.Contains(idTokenNonUserAttributes, attr) {
				userClaims[attr] = val
			}
		}
		logger.Debug("Extracted ID token claims", log.Int("noOfClaims", len(idTokenClaims)))
	}

	if len(o.GetOAuthProperties().Scopes) == 1 && slices.Contains(o.GetOAuthProperties().Scopes, "openid") {
		logger.Debug("No additional scopes configured.")
	} else {
		// Get user info using the access token
		userInfo, err := o.GetUserInfo(ctx, execResp, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get user info: %w", err)
		}
		if execResp.Status == flowconst.ExecFailure {
			return nil, nil
		}

		// If userID is still empty, try to resolve it using the sub claim from userInfo.
		// TODO: For now assume `sub` is the unique identifier for the user always.
		if userID == "" {
			sub, ok := userInfo["sub"]
			if !ok || sub == "" {
				execResp.Status = flowconst.ExecFailure
				execResp.FailureReason = "sub claim not found in the response."
				return nil, nil
			}
			userID, err = o.resolveUser(sub, ctx, execResp)
			if err != nil {
				return nil, err
			}
			if execResp.Status == flowconst.ExecFailure {
				return nil, nil
			}
		}

		for key, value := range userInfo {
			if key != "username" && key != "sub" && key != "id" {
				userClaims[key] = value
			}
		}
	}

	authenticatedUser := authncm.AuthenticatedUser{}
	if ctx.FlowType == flowconst.FlowTypeRegistration {
		authenticatedUser.IsAuthenticated = false
	} else {
		if userID == "" {
			execResp.Status = flowconst.ExecFailure
			execResp.FailureReason = "User not found"
			return nil, nil
		}
		userClaims["user_id"] = userID
		authenticatedUser.IsAuthenticated = true
		authenticatedUser.UserID = userID
	}

	// TODO: Need to convert attributes as per the IDP to local attribute mapping
	//  when the support is implemented.
	authenticatedUser.Attributes = userClaims

	return &authenticatedUser, nil
}

// resolveUser resolves the user based on the sub claim from user info.
func (o *OIDCAuthExecutor) resolveUser(sub string, ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) (string, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, o.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))

	user, svcErr := o.authService.GetInternalUser(sub)
	if svcErr != nil {
		if svcErr.Code == authncm.ErrorUserNotFound.Code {
			if ctx.FlowType == flowconst.FlowTypeRegistration {
				logger.Debug("User not found for the provided sub claim. Proceeding with registration flow.")
				execResp.Status = flowconst.ExecComplete
				execResp.FailureReason = ""

				if execResp.RuntimeData == nil {
					execResp.RuntimeData = make(map[string]string)
				}
				execResp.RuntimeData["sub"] = sub

				return "", nil
			} else {
				execResp.Status = flowconst.ExecFailure
				execResp.FailureReason = "User not found"
				return "", nil
			}
		} else {
			if svcErr.Type == serviceerror.ClientErrorType {
				execResp.Status = flowconst.ExecFailure
				execResp.FailureReason = svcErr.ErrorDescription
				return "", nil
			}

			logger.Error("Error while retrieving internal user", log.String("errorCode", svcErr.Code),
				log.String("description", svcErr.ErrorDescription))
			return "", errors.New("error while retrieving internal user")
		}
	}

	if ctx.FlowType == flowconst.FlowTypeRegistration {
		// At this point, a unique user is found in the system. Hence fail the execution.
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "User already exists with the provided sub claim."
		return "", nil
	}

	if user == nil || user.ID == "" {
		return "", errors.New("retrieved user is nil or has an empty ID")
	}

	return user.ID, nil
}
