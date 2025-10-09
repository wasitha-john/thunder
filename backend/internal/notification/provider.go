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

// Package notification contains the implementation of notification sender services.
package notification

import (
	"github.com/asgardeo/thunder/internal/system/jwt"
)

// TODO: This provider need to be removed once all usages are migrated to dependency injection.

// NotificationServiceProviderInterface defines the interface for the notification service provider
type NotificationServiceProviderInterface interface {
	GetNotificationSenderMgtService() NotificationSenderMgtSvcInterface
	GetOTPService() OTPServiceInterface
}

// NotificationServiceProvider is the implementation of NotificationServiceProviderInterface
type NotificationServiceProvider struct{}

// NewNotificationSenderServiceProvider creates a new instance of NotificationServiceProviderInterface
func NewNotificationSenderServiceProvider() NotificationServiceProviderInterface {
	return &NotificationServiceProvider{}
}

// GetNotificationSenderMgtService returns a notification sender management service instance
func (mnp *NotificationServiceProvider) GetNotificationSenderMgtService() NotificationSenderMgtSvcInterface {
	return newNotificationSenderMgtService()
}

// GetOTPService returns an OTP service instance
func (mnp *NotificationServiceProvider) GetOTPService() OTPServiceInterface {
	mgtService := newNotificationSenderMgtService()
	jwtService := jwt.GetJWTService()
	return newOTPService(mgtService, jwtService)
}
