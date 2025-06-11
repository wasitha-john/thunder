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

// Package client defines the interface for sending SMS messages and related implementations.
package client

import (
	"github.com/asgardeo/thunder/internal/notification/sms/model"
)

// SMSClientInterface defines the interface for sending SMS messages.
type SMSClientInterface interface {
	GetName() string
	SendSMS(sms model.SMSData) error
	validate(senderDTO model.SMSSenderDTO) error
}
