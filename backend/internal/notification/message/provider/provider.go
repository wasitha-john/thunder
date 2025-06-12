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

// Package provider provides functionality for managing message notification providers.
package provider

import (
	"errors"

	"github.com/asgardeo/thunder/internal/notification/message/client"
	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
)

// MessageClientProviderInterface defines the interface for the message client provider.
type MessageClientProviderInterface interface {
	Init() error
	GetMessageClient(name string) (client.MessageClientInterface, error)
}

// MessageClientProvider is the default implementation of the MessageClientProviderInterface.
type MessageClientProvider struct {
	messageClients map[string]client.MessageClientInterface
}

// NewMessageClientProvider creates a new instance of MessageClientProviderInterface.
func NewMessageClientProvider() MessageClientProviderInterface {
	return &MessageClientProvider{
		messageClients: make(map[string]client.MessageClientInterface),
	}
}

// Init initializes the message client provider by loading all available message clients.
func (sp *MessageClientProvider) Init() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageClientProvider"))
	logger.Debug("Initializing message client provider")

	msgProviderConfigs := config.GetThunderRuntime().Config.Provider.Message.Providers
	if len(msgProviderConfigs) == 0 {
		return errors.New("no message providers configured")
	}
	for _, providerConfig := range msgProviderConfigs {
		logger.Debug("Loading message provider", log.String("providerName", providerConfig.Name))

		senderDTO := model.MessageSenderDTO{
			Name:        providerConfig.Name,
			DisplayName: providerConfig.DisplayName,
			Description: providerConfig.Description,
			Properties:  providerConfig.Properties,
		}
		providerType := constants.MessageProviderType(providerConfig.Provider)
		var messageClient client.MessageClientInterface
		var err error
		switch providerType {
		case constants.MessageProviderTypeVonage:
			messageClient, err = client.NewVonageClient(senderDTO)
		case constants.MessageProviderTypeTwilio:
			messageClient, err = client.NewTwilioClient(senderDTO)
		case constants.MessageProviderTypeCustom:
			messageClient, err = client.NewCustomClient(senderDTO)
		default:
			return errors.New("unsupported message provider type: " + string(providerType))
		}

		if err != nil {
			logger.Error("Failed to create message client for provider",
				log.String("providerName", providerConfig.Name), log.Error(err))
			return errors.New("failed to create message client for provider " +
				providerConfig.Name + ": " + err.Error())
		}
		sp.messageClients[providerConfig.Name] = messageClient
		logger.Debug("Message provider loaded successfully", log.String("providerName", providerConfig.Name))
	}

	return nil
}

// GetMessageClient retrieves a message client by its name.
func (sp *MessageClientProvider) GetMessageClient(name string) (client.MessageClientInterface, error) {
	if msgClient, exists := sp.messageClients[name]; exists {
		return msgClient, nil
	}
	return nil, errors.New("Message client not found: " + name)
}
