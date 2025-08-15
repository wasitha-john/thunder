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

// Package provider provides functionality for managing message notification service.
package provider

import (
	"github.com/asgardeo/thunder/internal/notification/message/service"
)

// NotificationServiceProviderInterface defines the interface for the message notification service provider.
type NotificationServiceProviderInterface interface {
	GetMessageNotificationService() service.MessageNotificationServiceInterface
	GetMessageClientService() service.MessageClientServiceInterface
}

// NotificationServiceProvider is the default implementation of the NotificationServiceProviderInterface.
type NotificationServiceProvider struct{}

// NewNotificationServiceProvider creates a new instance of NotificationServiceProviderInterface.
func NewNotificationServiceProvider() NotificationServiceProviderInterface {
	return &NotificationServiceProvider{}
}

// GetMessageNotificationService returns the message notification service instance.
func (mnp *NotificationServiceProvider) GetMessageNotificationService() service.MessageNotificationServiceInterface {
	return service.GetMessageNotificationService()
}

// GetMessageClientService returns the message client service instance.
func (mnp *NotificationServiceProvider) GetMessageClientService() service.MessageClientServiceInterface {
	return service.GetMessageClientService()
}
