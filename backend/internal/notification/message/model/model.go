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

// Package model defines the data structures used for message notifications.
package model

import "github.com/asgardeo/thunder/internal/notification/message/constants"

// SMSData represents the data structure for a SMS message.
type SMSData struct {
	To   string `json:"to"`
	Body string `json:"body"`
}

// MessageSenderDTO represents the data object for a message sender configuration.
type MessageSenderDTO struct {
	Name        string                        `json:"name"`
	Provider    constants.MessageProviderType `json:"provider"`
	DisplayName string                        `json:"display_name"`
	Description string                        `json:"description"`
	Properties  map[string]string             `json:"properties"`
}

// SenderProperty represents a key-value property for a message notification sender.
type SenderProperty struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	IsSecret bool   `json:"is_secret"`
}

// MessageNotificationSender represents a message notification sender.
type MessageNotificationSender struct {
	ID          string                        `json:"id"`
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Provider    constants.MessageProviderType `json:"provider"`
	Properties  []SenderProperty              `json:"properties"`
}

// MessageNotificationSenderIn represents the input structure for creating a message notification sender.
type MessageNotificationSenderIn struct {
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Provider    constants.MessageProviderType `json:"provider"`
	Properties  []SenderProperty              `json:"properties"`
}

// MessageNotificationSenderRequest represents the request to create a message notification sender.
type MessageNotificationSenderRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Provider    string           `json:"provider"`
	Properties  []SenderProperty `json:"properties"`
}
