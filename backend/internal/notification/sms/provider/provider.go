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

// Package provider provides functionality for managing SMS notification providers.
package provider

import (
	"errors"

	"github.com/asgardeo/thunder/internal/notification/sms/client"
	"github.com/asgardeo/thunder/internal/notification/sms/constants"
	"github.com/asgardeo/thunder/internal/notification/sms/model"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
)

// SMSClientProviderInterface defines the interface for the SMS client provider.
type SMSClientProviderInterface interface {
	Init() error
	GetSMSClient(name string) (client.SMSClientInterface, error)
}

// SMSClientProvider is the default implementation of the SMSClientProviderInterface.
type SMSClientProvider struct {
	smsClients map[string]client.SMSClientInterface
}

// NewSMSClientProvider creates a new instance of SMSClientProviderInterface.
func NewSMSClientProvider() SMSClientProviderInterface {
	return &SMSClientProvider{
		smsClients: make(map[string]client.SMSClientInterface),
	}
}

// Init initializes the SMS client provider by loading all available SMS clients.
func (sp *SMSClientProvider) Init() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "SMSProvider"))
	logger.Debug("Initializing SMS providers...")

	smsProviderConfigs := config.GetThunderRuntime().Config.Provider.SMS.Providers
	if len(smsProviderConfigs) == 0 {
		return errors.New("no SMS providers configured")
	}
	for _, providerConfig := range smsProviderConfigs {
		logger.Debug("Loading SMS provider", log.String("providerName", providerConfig.Name))

		senderDTO := model.SMSSenderDTO{
			Name:        providerConfig.Name,
			DisplayName: providerConfig.DisplayName,
			Description: providerConfig.Description,
			Properties:  providerConfig.Properties,
		}
		providerType := constants.SMSProviderType(providerConfig.Provider)
		var smsClient client.SMSClientInterface
		var err error
		switch providerType {
		case constants.SMSProviderTypeVonage:
			smsClient, err = client.NewVonageClient(senderDTO)
		case constants.SMSProviderTypeTwilio:
			smsClient, err = client.NewTwilioClient(senderDTO)
		case constants.SMSProviderTypeCustom:
			smsClient, err = client.NewCustomClient(senderDTO)
		default:
			return errors.New("unsupported SMS provider type: " + string(providerType))
		}

		if err != nil {
			logger.Error("Failed to create SMS client for provider", log.String("providerName", providerConfig.Name),
				log.Error(err))
			return errors.New("failed to create SMS client for provider " + providerConfig.Name + ": " + err.Error())
		}
		sp.smsClients[providerConfig.Name] = smsClient
		logger.Debug("SMS provider loaded successfully", log.String("providerName", providerConfig.Name))
	}

	return nil
}

// GetSMSClient retrieves an SMS client by its name.
func (sp *SMSClientProvider) GetSMSClient(name string) (client.SMSClientInterface, error) {
	if smsClient, exists := sp.smsClients[name]; exists {
		return smsClient, nil
	}
	return nil, errors.New("SMS client not found: " + name)
}
