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

// Package service provides the functionality for managing message notification senders and clients.
package service

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	"github.com/asgardeo/thunder/internal/notification/message/store"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

var (
	instance *MessageNotificationService
	once     sync.Once
)

const loggerComponentName = "MessageNotificationMgtService"

// MessageNotificationServiceInterface defines the interface for message notification management service.
type MessageNotificationServiceInterface interface {
	CreateSender(sender model.MessageNotificationSenderIn) (*model.MessageNotificationSender,
		*serviceerror.ServiceError)
	ListSenders() ([]model.MessageNotificationSender, *serviceerror.ServiceError)
	GetSender(id string) (*model.MessageNotificationSender, *serviceerror.ServiceError)
	GetSenderByName(name string) (*model.MessageNotificationSender, *serviceerror.ServiceError)
	UpdateSender(id string, sender model.MessageNotificationSenderIn) (*model.MessageNotificationSender,
		*serviceerror.ServiceError)
	DeleteSender(id string) *serviceerror.ServiceError
}

// MessageNotificationService implements the NotificationServiceInterface.
type MessageNotificationService struct{}

// GetMessageNotificationService returns a singleton instance of MessageNotificationService.
func GetMessageNotificationService() MessageNotificationServiceInterface {
	once.Do(func() {
		instance = &MessageNotificationService{}
	})
	return instance
}

// CreateSender creates a new message notification sender.
func (s *MessageNotificationService) CreateSender(
	sender model.MessageNotificationSenderIn) (*model.MessageNotificationSender, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Creating message notification sender", log.String("name", sender.Name))

	if err := s.validateSender(sender); err != nil {
		return nil, err
	}
	notificationStore := store.GetMessageNotificationStore()

	// Check if sender with same name already exists
	senderRetv, err := notificationStore.GetSenderByName(sender.Name)
	if err != nil {
		logger.Error("Failed to retrieve message notification sender", log.String("name", sender.Name),
			log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}
	if senderRetv != nil {
		logger.Debug("Message notification sender already exists", log.String("name", sender.Name),
			log.String("id", senderRetv.ID))
		return nil, &constants.ErrorDuplicateSenderName
	}

	// Create the sender
	id, err := notificationStore.CreateSender(sender)
	if err != nil {
		logger.Error("Failed to create message notification sender", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return &model.MessageNotificationSender{
		ID:          id,
		Name:        sender.Name,
		Description: sender.Description,
		Provider:    sender.Provider,
		Properties:  sender.Properties,
	}, nil
}

// ListSenders retrieves all message notification senders.
func (s *MessageNotificationService) ListSenders() ([]model.MessageNotificationSender,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Listing all message notification senders")

	notificationStore := store.GetMessageNotificationStore()
	senders, err := notificationStore.ListSenders()
	if err != nil {
		logger.Error("Failed to list message notification senders", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return senders, nil
}

// GetSender retrieves a message notification sender by ID.
func (s *MessageNotificationService) GetSender(id string) (*model.MessageNotificationSender,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Retrieving message notification sender", log.String("id", id))

	if id == "" {
		return nil, &constants.ErrorInvalidSenderID
	}

	notificationStore := store.GetMessageNotificationStore()
	sender, err := notificationStore.GetSenderByID(id)
	if err != nil {
		logger.Error("Failed to retrieve message notification sender", log.String("id", id), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return sender, nil
}

// GetSenderByName retrieves a message notification sender by name.
func (s *MessageNotificationService) GetSenderByName(name string) (*model.MessageNotificationSender,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Retrieving message notification sender by name", log.String("name", name))

	if name == "" {
		return nil, &constants.ErrorInvalidSenderName
	}

	notificationStore := store.GetMessageNotificationStore()
	sender, err := notificationStore.GetSenderByName(name)
	if err != nil {
		logger.Error("Failed to retrieve message notification sender", log.String("name", name), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return sender, nil
}

// UpdateSender updates an existing message notification sender
func (s *MessageNotificationService) UpdateSender(id string,
	sender model.MessageNotificationSenderIn) (*model.MessageNotificationSender, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Updating message notification sender", log.String("id", id), log.String("name", sender.Name))

	if id == "" {
		return nil, &constants.ErrorInvalidSenderID
	}
	if err := s.validateSender(sender); err != nil {
		return nil, err
	}

	notificationStore := store.GetMessageNotificationStore()

	// Check if sender exists
	senderRetv, err := notificationStore.GetSenderByID(id)
	if err != nil {
		logger.Error("Failed to retrieve message notification sender", log.String("id", id), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}
	if senderRetv == nil {
		logger.Debug("Message notification sender not found", log.String("id", id))
		return nil, &constants.ErrorSenderNotFound
	}

	// Check for duplicate name
	senderRetvWName, err := notificationStore.GetSenderByName(sender.Name)
	if err != nil {
		logger.Error("Failed to retrieve message notification sender", log.String("name", sender.Name),
			log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}
	if senderRetvWName != nil && senderRetvWName.ID != id {
		logger.Debug("Another sender with the same name already exists",
			log.String("name", sender.Name), log.String("existingID", senderRetvWName.ID))
		return nil, &constants.ErrorDuplicateSenderName
	}

	// Update the sender
	if err := notificationStore.UpdateSender(id, sender); err != nil {
		logger.Error("Failed to update message notification sender", log.String("id", id), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return &model.MessageNotificationSender{
		ID:          id,
		Name:        sender.Name,
		Description: sender.Description,
		Provider:    sender.Provider,
		Properties:  sender.Properties,
	}, nil
}

// DeleteSender deletes a message notification sender
func (s *MessageNotificationService) DeleteSender(id string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Deleting message notification sender", log.String("id", id))

	if id == "" {
		return &constants.ErrorInvalidSenderID
	}

	notificationStore := store.GetMessageNotificationStore()
	if err := notificationStore.DeleteSender(id); err != nil {
		logger.Error("Failed to delete message notification sender", log.String("id", id), log.Error(err))
		return &constants.ErrorInternalServerError
	}

	return nil
}

// validateSender validates the message notification sender data.
func (s *MessageNotificationService) validateSender(
	sender model.MessageNotificationSenderIn) *serviceerror.ServiceError {
	if sender.Name == "" {
		return &constants.ErrorInvalidRequestFormat
	}
	if sender.Provider == "" {
		return &constants.ErrorInvalidProvider
	}

	if err := validateProviderProperties(sender); err != nil {
		svcErr := constants.ErrorInvalidRequestFormat
		svcErr.ErrorDescription = err.Error()
		return &svcErr
	}

	return nil
}

// validateProviderProperties validates the properties for a specific provider.
func validateProviderProperties(sender model.MessageNotificationSenderIn) error {
	if len(sender.Properties) == 0 {
		return errors.New("sender properties cannot be empty")
	}

	switch sender.Provider {
	case constants.MessageProviderTypeTwilio:
		return validateTwilioProperties(sender.Properties)
	case constants.MessageProviderTypeVonage:
		return validateVonageProperties(sender.Properties)
	case constants.MessageProviderTypeCustom:
		return validateCustomProperties(sender.Properties)
	default:
		return errors.New("unsupported provider")
	}
}

// validateTwilioProperties validates Twilio-specific properties.
func validateTwilioProperties(properties []model.SenderProperty) error {
	requiredProps := map[string]bool{
		"account_sid": false,
		"auth_token":  false,
		"sender_id":   false,
	}
	err := validateProperties(properties, requiredProps)
	if err != nil {
		return err
	}

	// Validate the account SID format
	sIDRegex := `^AC[0-9a-fA-F]{32}$`
	sid := ""
	for _, prop := range properties {
		if prop.Name == constants.TwilioPropKeyAccountSID {
			sid = prop.Value
			break
		}
	}
	matched, err := regexp.MatchString(sIDRegex, sid)
	if err != nil {
		return fmt.Errorf("failed to validate Twilio account SID: %w", err)
	}
	if !matched {
		return errors.New("invalid Twilio account SID format")
	}

	return nil
}

// validateVonageProperties validates Vonage-specific properties.
func validateVonageProperties(properties []model.SenderProperty) error {
	requiredProps := map[string]bool{
		"api_key":    false,
		"api_secret": false,
		"sender_id":  false,
	}
	return validateProperties(properties, requiredProps)
}

// validateCustomProperties validates custom provider properties.
func validateCustomProperties(properties []model.SenderProperty) error {
	url := ""
	httpMethod := ""
	contentType := ""
	for _, prop := range properties {
		if prop.Name == "" {
			return errors.New("properties must have non-empty name")
		}
		if prop.Name == constants.CustomPropKeyURL {
			url = prop.Value
		} else if prop.Name == constants.CustomPropKeyHTTPMethod {
			httpMethod = strings.ToUpper(prop.Value)
		}
		if prop.Name == constants.CustomPropKeyContentType {
			contentType = strings.ToUpper(prop.Value)
		}
	}
	if url == "" {
		return errors.New("custom provider must have a URL property")
	}
	if httpMethod != "" && httpMethod != http.MethodGet &&
		httpMethod != http.MethodPost && httpMethod != http.MethodPut {
		return errors.New("custom provider must have a valid HTTP method")
	}
	if contentType != "" && contentType != "JSON" && contentType != "FORM" {
		return errors.New("custom provider must have a valid content type (JSON or FORM)")
	}

	return nil
}

// validateProperties validates the properties for a message notification sender.
func validateProperties(properties []model.SenderProperty, requiredProperties map[string]bool) error {
	for _, prop := range properties {
		if prop.Name == "" {
			return errors.New("properties must have non-empty name")
		}
		if _, exists := requiredProperties[prop.Name]; exists {
			requiredProperties[prop.Name] = true
		}
	}

	// Check if all required properties are present
	for key, found := range requiredProperties {
		if !found {
			return errors.New("required property missing for the provider: " + key)
		}
	}
	return nil
}
