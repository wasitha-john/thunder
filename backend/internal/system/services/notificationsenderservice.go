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
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// NotificationSenderService provides HTTP endpoints for managing message notification senders.
type NotificationSenderService struct {
	messageNotificationHandler *notification.MessageNotificationSenderHandler
}

// NewNotificationSenderService creates a new instance of NotificationSenderService.
func NewNotificationSenderService(mux *http.ServeMux) ServiceInterface {
	instance := &NotificationSenderService{
		messageNotificationHandler: notification.NewMessageNotificationSenderHandler(),
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the HTTP routes for the NotificationSenderService.
func (s *NotificationSenderService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /notification-senders/message",
		s.messageNotificationHandler.HandleSenderListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("POST /notification-senders/message",
		s.messageNotificationHandler.HandleSenderCreateRequest, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   "GET, PUT, DELETE",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /notification-senders/message/{id}",
		s.messageNotificationHandler.HandleSenderGetRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /notification-senders/message/{id}",
		s.messageNotificationHandler.HandleSenderUpdateRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /notification-senders/message/{id}",
		s.messageNotificationHandler.HandleSenderDeleteRequest, opts2))

	opts3 := middleware.CORSOptions{
		AllowedMethods:   "POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /notification-senders/otp/send",
		s.messageNotificationHandler.HandleOTPSendRequest, opts3))
	mux.HandleFunc(middleware.WithCORS("POST /notification-senders/otp/verify",
		s.messageNotificationHandler.HandleOTPVerifyRequest, opts3))
}
