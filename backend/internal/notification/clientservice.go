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

package notification

import (
	"github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/notification/message"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// NotificationClientServiceInterface defines the interface for the notification client service.
type NotificationClientServiceInterface interface {
	GetMessageClientByName(senderName string) (message.MessageClientInterface, *serviceerror.ServiceError)
}

// notificationClientService is the implementation of NotificationClientServiceInterface.
type notificationClientService struct{}

// getNotificationClientService returns a new instance of the NotificationClientServiceInterface.
func getNotificationClientService() NotificationClientServiceInterface {
	return &notificationClientService{}
}

// GetMessageClientByName returns the message client for the given sender name.
func (mcs *notificationClientService) GetMessageClientByName(senderName string) (message.MessageClientInterface,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationClientService"))
	logger.Debug("Retrieving message client for sender", log.String("senderName", senderName))

	mgtService := getNotificationSenderMgtService()
	sender, svcErr := mgtService.GetSenderByName(senderName)
	if svcErr != nil {
		logger.Error("Failed to retrieve sender by name", log.String("senderName", senderName),
			log.Any("serviceError", svcErr))
		return nil, svcErr
	}
	if sender == nil {
		logger.Error("Sender not found", log.String("senderName", senderName))
		return nil, &ErrorSenderNotFound
	}
	if sender.Type != common.NotificationSenderTypeMessage {
		logger.Error("Sender is not of type MESSAGE", log.String("senderName", senderName),
			log.String("senderType", string(sender.Type)))
		return nil, &ErrorRequestedSenderIsNotOfExpectedType
	}

	client, err := getMessageClient(*sender)
	if err != nil {
		return nil, err
	}
	return *client, nil
}

// getMessageClient retrieves the message client based on the sender's provider type.
func getMessageClient(sender common.NotificationSenderDTO) (*message.MessageClientInterface,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationClientService"))

	var _client message.MessageClientInterface
	var err error
	switch sender.Provider {
	case common.MessageProviderTypeVonage:
		_client, err = message.NewVonageClient(sender)
	case common.MessageProviderTypeTwilio:
		_client, err = message.NewTwilioClient(sender)
	case common.MessageProviderTypeCustom:
		_client, err = message.NewCustomClient(sender)
	default:
		logger.Error("Unsupported message provider", log.String("provider", string(sender.Provider)))
		return nil, &ErrorInvalidProvider
	}

	if err != nil {
		logger.Error("Failed to create message client", log.String("provider", string(sender.Provider)),
			log.Error(err))
		return nil, &ErrorInternalServerError
	}

	return &_client, nil
}
