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

package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/notification/message/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// NotificationSenderService provides HTTP endpoints for managing message notification senders.
type NotificationSenderService struct {
	ServerOpsService    server.ServerOperationServiceInterface
	notificationHandler *handler.MessageNotificationHandler
}

// NewNotificationSenderService creates a new instance of NotificationSenderService.
func NewNotificationSenderService(mux *http.ServeMux) ServiceInterface {
	instance := &NotificationSenderService{
		ServerOpsService:    server.NewServerOperationService(),
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
	s.ServerOpsService.WrapHandleFunction(mux, "GET /notification-senders/message", &opts,
		s.notificationHandler.HandleSenderListRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "POST /notification-senders/message", &opts,
		s.notificationHandler.HandleSenderCreateRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "GET /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderGetRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "PUT /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderUpdateRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "DELETE /notification-senders/message/{id}", &opts,
		s.notificationHandler.HandleSenderDeleteRequest)
}
