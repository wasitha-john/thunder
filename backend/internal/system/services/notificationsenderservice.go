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

package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/notification/message/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// NotificationSenderService provides HTTP endpoints for managing message notification senders.
type NotificationSenderService struct {
	notificationHandler *handler.MessageNotificationHandler
}

// NewNotificationSenderService creates a new instance of NotificationSenderService.
func NewNotificationSenderService(mux *http.ServeMux) *NotificationSenderService {
	instance := &NotificationSenderService{
		notificationHandler: handler.NewMessageNotificationHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the HTTP routes for the NotificationSenderService.
func (s *NotificationSenderService) RegisterRoutes(mux *http.ServeMux) {
	opts := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, POST, PUT, DELETE",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	server.WrapHandleFunction(mux, "GET /notification-senders/message", &opts,
		s.notificationHandler.HandleSenderListRequest)
	server.WrapHandleFunction(mux, "POST /notification-senders/message", &opts,
		s.notificationHandler.HandleSenderCreateRequest)
	server.WrapHandleFunction(mux, "GET /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderGetRequest)
	server.WrapHandleFunction(mux, "PUT /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderUpdateRequest)
	server.WrapHandleFunction(mux, "DELETE /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderDeleteRequest)
}
