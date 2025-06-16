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

// Package smsauth provides the implementation of SMS OTP authentication executor.
package smsauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	authnmodel "github.com/asgardeo/thunder/internal/authn/model"
	flowconst "github.com/asgardeo/thunder/internal/flow/constants"
	flowmodel "github.com/asgardeo/thunder/internal/flow/model"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	msgsenderprovider "github.com/asgardeo/thunder/internal/notification/message/provider"
	"github.com/asgardeo/thunder/internal/system/log"
	userprovider "github.com/asgardeo/thunder/internal/user/provider"
)

const (
	loggerComponentName = "SMSOTPAuthExecutor"
	errorInvalidOTP     = "invalid OTP provided"
)

// SMSOTPAuthExecutor implements the ExecutorInterface for SMS OTP authentication.
type SMSOTPAuthExecutor struct {
	internal   flowmodel.Executor
	senderName string
}

// NewSMSOTPAuthExecutor creates a new instance of SMSOTPAuthExecutor.
func NewSMSOTPAuthExecutor(id, name, senderName string) flowmodel.ExecutorInterface {
	defaultInputs := []flowmodel.InputData{
		{
			Name:     "otp",
			Type:     "string",
			Required: true,
		},
	}
	prerequisites := []flowmodel.InputData{
		{
			Name:     "username",
			Type:     "string",
			Required: true,
		},
	}

	return &SMSOTPAuthExecutor{
		internal:   *flowmodel.NewExecutor(id, name, defaultInputs, prerequisites),
		senderName: senderName,
	}
}

// GetID returns the ID of the SMSOTPAuthExecutor.
func (s *SMSOTPAuthExecutor) GetID() string {
	return s.internal.GetID()
}

// GetName returns the name of the SMSOTPAuthExecutor.
func (s *SMSOTPAuthExecutor) GetName() string {
	return s.internal.GetName()
}

// GetProperties returns the properties of the SMSOTPAuthExecutor.
func (s *SMSOTPAuthExecutor) GetProperties() flowmodel.ExecutorProperties {
	return s.internal.Properties
}

// Execute executes the SMS OTP authentication logic.
func (s *SMSOTPAuthExecutor) Execute(ctx *flowmodel.NodeContext) (*flowmodel.ExecutorResponse, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, s.GetID()),
		log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing SMS OTP authentication executor")

	execResp := &flowmodel.ExecutorResponse{}

	if !s.ValidatePrerequisites(ctx, execResp) {
		logger.Debug("Prerequisites not met for SMS OTP authentication executor")
		return execResp, nil
	}

	if s.CheckInputData(ctx, execResp) {
		err := s.InitiateOTP(ctx, execResp)
		if err != nil {
			return execResp, err
		}
	} else {
		err := s.ProcessAuthFlowResponse(ctx, execResp)
		if err != nil {
			return execResp, err
		}
	}

	logger.Debug("SMS OTP authentication executor execution completed",
		log.String("status", string(execResp.Status)),
		log.Bool("isAuthenticated", execResp.AuthenticatedUser.IsAuthenticated))

	return execResp, nil
}

// InitiateOTP initiates the OTP sending process to the user's mobile number.
func (s *SMSOTPAuthExecutor) InitiateOTP(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, s.GetID()), log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Sending SMS OTP to user")

	username := ctx.UserInputData["username"]

	userID, mobileNumber, err := s.getUserMobileNumber(username, execResp, logger)
	if err != nil {
		logger.Error("Failed to retrieve user mobile number", log.Error(err))
		return fmt.Errorf("failed to retrieve user mobile number: %w", err)
	}
	if execResp.Status == flowconst.ExecFailure {
		return nil
	}

	if err := s.generateAndSendOTP(username, mobileNumber, ctx, execResp, logger); err != nil {
		logger.Error("Failed to send OTP", log.Error(err))
		return fmt.Errorf("failed to send OTP: %w", err)
	}
	if execResp.Status == flowconst.ExecFailure {
		return nil
	}

	// Store the user ID in runtime data for later use.
	if execResp.RuntimeData == nil {
		execResp.RuntimeData = make(map[string]string)
	}
	execResp.RuntimeData["userID"] = userID

	logger.Debug("SMS OTP sent successfully")
	execResp.Status = flowconst.ExecUserInputRequired
	return nil
}

// ProcessAuthFlowResponse processes the authentication flow response for SMS OTP.
func (s *SMSOTPAuthExecutor) ProcessAuthFlowResponse(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName),
		log.String(log.LoggerKeyExecutorID, s.GetID()), log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Processing authentication flow response for SMS OTP")

	username := ctx.UserInputData["username"]

	err := s.validateOTP(ctx, execResp, logger)
	if err != nil {
		logger.Error("Error validating OTP", log.Error(err))
		return fmt.Errorf("error validating OTP: %w", err)
	}
	if execResp.Status == flowconst.ExecFailure {
		return nil
	}

	userID := ctx.RuntimeData["userID"]
	if userID == "" {
		logger.Error("User ID not found in context runtime data", log.String("username", log.MaskString(username)))
		return errors.New("user ID not found in context runtime data")
	}

	authenticatedUser, err := s.getAuthenticatedUser(userID)
	if err != nil {
		logger.Error("Failed to get authenticated user details", log.Error(err))
		return fmt.Errorf("failed to get authenticated user details: %w", err)
	}

	execResp.AuthenticatedUser = *authenticatedUser
	execResp.Status = flowconst.ExecComplete
	return nil
}

// GetDefaultExecutorInputs returns the default required input data for the SMSOTPAuthExecutor.
func (s *SMSOTPAuthExecutor) GetDefaultExecutorInputs() []flowmodel.InputData {
	return s.internal.DefaultExecutorInputs
}

// GetPrerequisites returns the prerequisites for the SMSOTPAuthExecutor.
func (s *SMSOTPAuthExecutor) GetPrerequisites() []flowmodel.InputData {
	return s.internal.Prerequisites
}

// CheckInputData checks if the required input data is provided in the context.
func (s *SMSOTPAuthExecutor) CheckInputData(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse) bool {
	return s.internal.CheckInputData(ctx, execResp)
}

// ValidatePrerequisites validates whether the prerequisites for the SMSOTPAuthExecutor are met.
func (s *SMSOTPAuthExecutor) ValidatePrerequisites(ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse) bool {
	return s.internal.ValidatePrerequisites(ctx, execResp)
}

// getUserMobileNumber retrieves the mobile number for the given username.
// It returns the user ID, mobile number, and any error encountered.
func (s *SMSOTPAuthExecutor) getUserMobileNumber(username string, execResp *flowmodel.ExecutorResponse,
	logger *log.Logger) (string, string, error) {
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()

	userID, err := userService.IdentityUser("username", username)
	if err != nil {
		logger.Error("Failed to identify user by username",
			log.String("username", log.MaskString(username)), log.Error(err))
		return "", "", fmt.Errorf("failed to retrieve user ID: %w", err)
	}
	if userID == nil || *userID == "" {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "User not found for the provided username"
		return "", "", nil
	}

	user, err := userService.GetUser(*userID)
	if err != nil {
		logger.Error("Failed to retrieve user details", log.String("userID", *userID), log.Error(err))
		return "", "", fmt.Errorf("failed to retrieve user details: %w", err)
	}

	// Extract mobile number from user attributes
	var attrs map[string]interface{}
	if err := json.Unmarshal(user.Attributes, &attrs); err != nil {
		logger.Error("Failed to unmarshal user attributes", log.Error(err))
		return "", "", fmt.Errorf("failed to unmarshal user attributes: %w", err)
	}
	mobileNumber, ok := attrs["mobileNumber"].(string)
	if !ok || mobileNumber == "" {
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "Mobile number not found or invalid in user attributes"
		return *userID, "", nil
	}

	return *userID, mobileNumber, nil
}

// generateAndSendOTP generates an OTP and sends it to the user's mobile number.
func (s *SMSOTPAuthExecutor) generateAndSendOTP(username, mobileNumber string, ctx *flowmodel.NodeContext,
	execResp *flowmodel.ExecutorResponse, logger *log.Logger) error {
	attemptCount, err := s.validateAttempts(ctx, execResp, logger)
	if err != nil {
		return fmt.Errorf("failed to validate OTP attempts: %w", err)
	}
	if execResp.Status == flowconst.ExecFailure {
		return nil
	}

	otp, err := s.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	logger.Debug("Sending OTP to user's mobile", log.String("username", log.MaskString(username)))

	smsData := model.SMSData{
		To: mobileNumber,
		// TODO: This should be handled with a SMS template.
		Body: fmt.Sprintf("Your verification code is: %s. This code is valid for %d minutes.",
			otp.Value, otp.ValidityPeriodInMillis/60000),
	}

	// Send the SMS OTP.
	provider := msgsenderprovider.NewNotificationServiceProvider()
	service := provider.GetMessageClientService()
	msgClient, svcErr := service.GetMessageClientByName(s.senderName)
	if svcErr != nil {
		logger.Error("Failed to get message client", log.String("senderName", s.senderName),
			log.Any("serviceError", svcErr))
		return fmt.Errorf("failed to get message client: %s", svcErr.ErrorDescription)
	}
	if msgClient == nil {
		return fmt.Errorf("message client %s not found", s.senderName)
	}

	if err := msgClient.SendSMS(smsData); err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	// Store runtime data.
	if execResp.RuntimeData == nil {
		execResp.RuntimeData = make(map[string]string)
	}
	execResp.RuntimeData["value"] = otp.Value
	execResp.RuntimeData["expiryTimeInMillis"] = fmt.Sprintf("%d", otp.ExpiryTimeInMillis)
	execResp.RuntimeData["attemptCount"] = strconv.Itoa(attemptCount + 1)

	return nil
}

// validateAttempts checks if the maximum number of OTP attempts has been reached.
func (s *SMSOTPAuthExecutor) validateAttempts(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	logger *log.Logger) (int, error) {
	username := ctx.UserInputData["username"]
	attemptCount := 0

	attemptCountStr := ctx.RuntimeData["attemptCount"]
	if attemptCountStr != "" {
		count, err := strconv.Atoi(attemptCountStr)
		if err != nil {
			logger.Error("Failed to parse attempt count", log.Error(err))
			return 0, fmt.Errorf("failed to parse attempt count: %w", err)
		}
		attemptCount = count
	}

	if attemptCount >= s.getOTPMaxAttempts() {
		logger.Debug("Maximum OTP attempts reached", log.String("username", log.MaskString(username)),
			log.Int("attemptCount", attemptCount))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = fmt.Sprintf("maximum OTP attempts reached: %d", attemptCount)
		return 0, nil
	}

	return attemptCount, nil
}

// generateOTP generates a random OTP based on the configurations.
func (s *SMSOTPAuthExecutor) generateOTP() (model.OTP, error) {
	charSet := s.getOTPCharset()
	otpLength := s.getOTPLength()

	chars := []rune(charSet)
	result := make([]rune, otpLength)

	for i := 0; i < otpLength; i++ {
		max := big.NewInt(int64(len(chars)))
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return model.OTP{}, fmt.Errorf("failed to generate random number: %w", err)
		}
		result[i] = chars[n.Int64()]
	}

	token := string(result)
	currentTime := time.Now().UnixMilli()
	validityPeriod := s.getOTPValidityPeriodInMillis()

	return model.OTP{
		Value:                  token,
		GeneratedTimeInMillis:  currentTime,
		ValidityPeriodInMillis: validityPeriod,
		ExpiryTimeInMillis:     currentTime + validityPeriod,
	}, nil
}

// getOTPCharset returns the character set for OTP generation.
func (s *SMSOTPAuthExecutor) getOTPCharset() string {
	if s.useOnlyNumericChars() {
		return "9245378016"
	}
	return "KIGXHOYSPRWCEFMVUQLZDNABJT9245378016"
}

// getOTPMaxAttempts returns the maximum number of attempts allowed for OTP validation.
func (s *SMSOTPAuthExecutor) getOTPMaxAttempts() int {
	// TODO: This needs to be configured as a IDP property.
	return 3
}

// getOTPLength returns the length of the OTP.
func (s *SMSOTPAuthExecutor) getOTPLength() int {
	// TODO: This needs to be configured as a IDP property.
	return 6
}

// useOnlyNumericChars determines whether to use only numeric characters.
func (s *SMSOTPAuthExecutor) useOnlyNumericChars() bool {
	// TODO: This needs to be configured as a IDP property.
	return true
}

// getOTPValidityPeriodInMillis returns the validity period of the OTP in milliseconds.
func (s *SMSOTPAuthExecutor) getOTPValidityPeriodInMillis() int64 {
	// TODO: This needs to be configured as a IDP property.
	return 120000 // 2 minutes
}

// validateOTP validates the OTP for the given user and mobile number.
func (s *SMSOTPAuthExecutor) validateOTP(ctx *flowmodel.NodeContext, execResp *flowmodel.ExecutorResponse,
	logger *log.Logger) error {
	username := ctx.UserInputData["username"]
	providedOTP := ctx.UserInputData["otp"]

	logger.Debug("Validating OTP", log.String("username", log.MaskString(username)))

	if providedOTP == "" {
		logger.Debug("Provided OTP is empty", log.String("username", log.MaskString(username)))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = errorInvalidOTP
		return nil
	}

	storedOTP := ctx.RuntimeData["value"]
	if storedOTP == "" {
		logger.Debug("No stored OTP found for validation", log.String("username", log.MaskString(username)))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = errorInvalidOTP
		return nil
	}

	// Validate for the OTP value
	if providedOTP != storedOTP {
		logger.Debug("Provided OTP does not match stored OTP", log.String("username", log.MaskString(username)))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = errorInvalidOTP
		return nil
	}

	// Validate for the expiry time of the OTP
	expiryTimeStr := ctx.RuntimeData["expiryTimeInMillis"]
	if expiryTimeStr == "" {
		logger.Debug("No expiry time found for stored OTP", log.String("username", log.MaskString(username)))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = errorInvalidOTP
		return nil
	}
	expiryTime, err := strconv.ParseInt(expiryTimeStr, 10, 64)
	if err != nil {
		logger.Error("Failed to parse expiry time for OTP", log.String("username", log.MaskString(username)),
			log.Error(err))
		return errors.New("something went wrong while validating the OTP")
	}

	currentTime := time.Now().UnixMilli()
	if currentTime > expiryTime {
		execResp.RuntimeData["value"] = ""
		execResp.RuntimeData["expiryTimeInMillis"] = ""
		logger.Debug("OTP has expired", log.String("username", log.MaskString(username)))
		execResp.Status = flowconst.ExecFailure
		execResp.FailureReason = "OTP has expired"
		return nil
	}

	execResp.RuntimeData["value"] = ""
	execResp.RuntimeData["expiryTimeInMillis"] = ""
	logger.Debug("OTP validated successfully", log.String("username", log.MaskString(username)))
	return nil
}

// getAuthenticatedUser returns the authenticated user details for the given user ID.
func (s *SMSOTPAuthExecutor) getAuthenticatedUser(userID string) (*authnmodel.AuthenticatedUser, error) {
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()

	// Get the complete user information
	user, err := userService.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user details: %w", err)
	}

	// Extract user attributes
	var attrs map[string]interface{}
	if err := json.Unmarshal(user.Attributes, &attrs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user attributes: %w", err)
	}

	// Create the authenticated user object
	authenticatedUser := &authnmodel.AuthenticatedUser{
		IsAuthenticated: true,
		UserID:          user.ID,
		Attributes: map[string]string{
			"email":        attrs["email"].(string),
			"firstName":    attrs["firstName"].(string),
			"lastName":     attrs["lastName"].(string),
			"mobileNumber": attrs["mobileNumber"].(string),
		},
	}

	return authenticatedUser, nil
}
