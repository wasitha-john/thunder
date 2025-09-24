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

	"github.com/asgardeo/thunder/internal/notification"
	"github.com/asgardeo/thunder/internal/system/server"
)

// NotificationSenderService provides HTTP endpoints for managing message notification senders.
type NotificationSenderService struct {
	ServerOpsService           server.ServerOperationServiceInterface
	messageNotificationHandler *notification.MessageNotificationSenderHandler
}

// NewNotificationSenderService creates a new instance of NotificationSenderService.
func NewNotificationSenderService(mux *http.ServeMux) ServiceInterface {
	instance := &NotificationSenderService{
		ServerOpsService:           server.NewServerOperationService(),
		messageNotificationHandler: notification.NewMessageNotificationSenderHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the HTTP routes for the NotificationSenderService.
func (s *NotificationSenderService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.ServerOpsService.WrapHandleFunction(mux, "GET /notification-senders/message", &opts1,
		s.messageNotificationHandler.HandleSenderListRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "POST /notification-senders/message", &opts1,
		s.messageNotificationHandler.HandleSenderCreateRequest)

	opts2 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, PUT, DELETE",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.ServerOpsService.WrapHandleFunction(mux, "GET /notification-senders/message/{id}", &opts2,
		s.messageNotificationHandler.HandleSenderGetRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "PUT /notification-senders/message/{id}", &opts2,
		s.messageNotificationHandler.HandleSenderUpdateRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "DELETE /notification-senders/message/{id}", &opts2,
		s.messageNotificationHandler.HandleSenderDeleteRequest)

	opts3 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	s.ServerOpsService.WrapHandleFunction(mux, "POST /notification-senders/otp/send", &opts3,
		s.messageNotificationHandler.HandleOTPSendRequest)
	s.ServerOpsService.WrapHandleFunction(mux, "POST /notification-senders/otp/verify", &opts3,
		s.messageNotificationHandler.HandleOTPVerifyRequest)
}
