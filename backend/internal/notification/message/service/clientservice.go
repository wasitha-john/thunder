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

package service

import (
	"sync"

	"github.com/asgardeo/thunder/internal/notification/message/client"
	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

var (
	clientInstance *MessageClientService
	clientOnce     sync.Once
)

const clientServiceLoggerComponentName = "MessageClientService"

// MessageClientServiceInterface defines the interface for the message client service.
type MessageClientServiceInterface interface {
	GetMessageClientByName(senderName string) (client.MessageClientInterface, *serviceerror.ServiceError)
}

// MessageClientService is the default implementation of the MessageClientServiceInterface.
type MessageClientService struct{}

// GetMessageClientService returns the singleton instance of MessageClientServiceInterface.
func GetMessageClientService() MessageClientServiceInterface {
	clientOnce.Do(func() {
		clientInstance = &MessageClientService{}
	})

	return clientInstance
}

// GetMessageClientByName returns the message client for the given sender name.
func (mcs *MessageClientService) GetMessageClientByName(senderName string) (client.MessageClientInterface,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, clientServiceLoggerComponentName))
	logger.Debug("Retrieving message client for sender", log.String("senderName", senderName))

	mgtService := GetMessageNotificationService()
	sender, svcErr := mgtService.GetSenderByName(senderName)
	if svcErr != nil {
		logger.Error("Failed to retrieve sender by name", log.String("senderName", senderName),
			log.Any("serviceError", svcErr))
		return nil, svcErr
	}
	if sender == nil {
		logger.Error("Sender not found", log.String("senderName", senderName))
		return nil, &constants.ErrorSenderNotFound
	}

	client, err := getMessageClient(*sender)
	if err != nil {
		return nil, err
	}
	return *client, nil
}

// getMessageClient retrieves the message client based on the sender's provider type.
func getMessageClient(sender model.MessageNotificationSender) (*client.MessageClientInterface,
	*serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, clientServiceLoggerComponentName))

	var _client client.MessageClientInterface
	var err error
	switch sender.Provider {
	case constants.MessageProviderTypeVonage:
		_client, err = client.NewVonageClient(sender)
	case constants.MessageProviderTypeTwilio:
		_client, err = client.NewTwilioClient(sender)
	case constants.MessageProviderTypeCustom:
		_client, err = client.NewCustomClient(sender)
	default:
		logger.Error("Unsupported message provider", log.String("provider", string(sender.Provider)))
		return nil, &constants.ErrorInvalidProvider
	}

	if err != nil {
		logger.Error("Failed to create message client", log.String("provider", string(sender.Provider)),
			log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	return &_client, nil
}
