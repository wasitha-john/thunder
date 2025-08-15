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

// Package handler provides HTTP handlers for managing message notification senders.
package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/asgardeo/thunder/internal/notification/message/constants"
	"github.com/asgardeo/thunder/internal/notification/message/model"
	"github.com/asgardeo/thunder/internal/notification/message/service"
	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// MessageNotificationHandler handles HTTP requests for message notification senders
type MessageNotificationHandler struct{}

// NewMessageNotificationHandler creates a new instance of MessageNotificationHandler
func NewMessageNotificationHandler() *MessageNotificationHandler {
	return &MessageNotificationHandler{}
}

// HandleSenderListRequest handles the request to list all message notification senders
func (h *MessageNotificationHandler) HandleSenderListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageNotificationHandler"))

	svc := service.GetMessageNotificationService()
	senders, svcErr := svc.ListSenders()
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	senderResponses := make([]model.MessageNotificationSender, 0, len(senders))
	for _, sender := range senders {
		senderResponses = append(senderResponses, getMessageNotificationSenderResponse(&sender))
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(senderResponses); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	logger.Debug("Successfully listed message notification senders")
}

// HandleSenderCreateRequest handles the request to create a new message notification sender
func (h *MessageNotificationHandler) HandleSenderCreateRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageNotificationHandler"))

	sender, err := sysutils.DecodeJSONBody[model.MessageNotificationSenderRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: "Failed to parse request body: " + err.Error(),
		}

		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	if !isValidProvider(sender.Provider) {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidProvider.Code,
			Message:     constants.ErrorInvalidProvider.Error,
			Description: "Invalid provider type: " + sender.Provider,
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	notificationSender := getSenderFromSenderRequest(sender)

	svc := service.GetMessageNotificationService()
	createdSender, svcErr := svc.CreateSender(*notificationSender)
	if svcErr != nil {
		if svcErr.Code == constants.ErrorDuplicateSenderName.Code {
			w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
			w.WriteHeader(http.StatusConflict)

			errResp := apierror.ErrorResponse{
				Code:        svcErr.Code,
				Message:     svcErr.Error,
				Description: svcErr.ErrorDescription,
			}

			if err := json.NewEncoder(w).Encode(errResp); err != nil {
				logger.Error("Error encoding error response", log.Error(err))
				http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			}
			return
		}

		h.handleError(w, logger, svcErr)
		return
	}

	senderResponse := getMessageNotificationSenderResponse(createdSender)

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(senderResponse); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	logger.Debug("Successfully created message notification sender", log.String("id", createdSender.ID))
}

// HandleSenderGetRequest handles the request to get a message notification sender by ID
func (h *MessageNotificationHandler) HandleSenderGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageNotificationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/notification-senders/message/")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	svc := service.GetMessageNotificationService()
	sender, svcErr := svc.GetSender(id)
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}
	if sender == nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusNotFound)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorSenderNotFound.Code,
			Message:     constants.ErrorSenderNotFound.Error,
			Description: constants.ErrorSenderNotFound.ErrorDescription,
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	senderResponse := getMessageNotificationSenderResponse(sender)

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(senderResponse); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	logger.Debug("Successfully retrieved message notification sender", log.String("id", id))
}

// HandleSenderUpdateRequest handles the request to update a message notification sender
func (h *MessageNotificationHandler) HandleSenderUpdateRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageNotificationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/notification-senders/message/")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	sender, err := sysutils.DecodeJSONBody[model.MessageNotificationSenderRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: "Failed to parse request body: " + err.Error(),
		}

		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	if !isValidProvider(sender.Provider) {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidProvider.Code,
			Message:     constants.ErrorInvalidProvider.Error,
			Description: "Invalid provider type: " + sender.Provider,
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	notificationSender := getSenderFromSenderRequest(sender)

	svc := service.GetMessageNotificationService()
	updatedSender, svcErr := svc.UpdateSender(id, *notificationSender)

	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(updatedSender); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	logger.Debug("Successfully updated message notification sender", log.String("id", id))
}

// HandleSenderDeleteRequest handles the request to delete a message notification sender
func (h *MessageNotificationHandler) HandleSenderDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MessageNotificationHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/notification-senders/message/")
	if id == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        constants.ErrorInvalidRequestFormat.Code,
			Message:     constants.ErrorInvalidRequestFormat.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	svc := service.GetMessageNotificationService()
	svcErr := svc.DeleteSender(id)
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	logger.Debug("Successfully deleted message notification sender", log.String("id", id))
}

// handleError handles service errors and returns appropriate HTTP responses.
func (h *MessageNotificationHandler) handleError(w http.ResponseWriter, logger *log.Logger,
	svcErr *serviceerror.ServiceError) {
	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)

	errResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}

	statusCode := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		switch svcErr.Code {
		case constants.ErrorSenderNotFound.Code:
			statusCode = http.StatusNotFound
		case constants.ErrorDuplicateSenderName.Code:
			statusCode = http.StatusConflict
		default:
			statusCode = http.StatusBadRequest
		}
	}
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error("Error encoding error response", log.Error(err))
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}

// getSenderFromSenderRequest sanitizes the sender request and converts it to a MessageNotificationSender model.
func getSenderFromSenderRequest(sender *model.MessageNotificationSenderRequest) *model.MessageNotificationSenderIn {
	name := sysutils.SanitizeString(sender.Name)
	description := sysutils.SanitizeString(sender.Description)
	providerStr := sysutils.SanitizeString(sender.Provider)

	// Sanitize properties
	properties := make([]model.SenderProperty, 0, len(sender.Properties))
	for _, prop := range sender.Properties {
		properties = append(properties, model.SenderProperty{
			Name:     sysutils.SanitizeString(prop.Name),
			Value:    sysutils.SanitizeString(prop.Value),
			IsSecret: prop.IsSecret,
		})
	}

	notificationSender := model.MessageNotificationSenderIn{
		Name:        name,
		Description: description,
		Provider:    constants.MessageProviderType(providerStr),
		Properties:  properties,
	}
	return &notificationSender
}

// isValidProvider checks if the given provider is a valid message provider type
func isValidProvider(provider string) bool {
	switch provider {
	case string(constants.MessageProviderTypeVonage),
		string(constants.MessageProviderTypeTwilio),
		string(constants.MessageProviderTypeCustom):
		return true
	default:
		return false
	}
}

// getMessageNotificationSenderResponse converts a MessageNotificationSender model to a response model,
func getMessageNotificationSenderResponse(
	sender *model.MessageNotificationSender) model.MessageNotificationSender {
	returnSender := model.MessageNotificationSender{
		ID:          sender.ID,
		Name:        sender.Name,
		Description: sender.Description,
		Provider:    sender.Provider,
	}

	// Mask secret properties in the response.
	senderProperties := make([]model.SenderProperty, 0, len(sender.Properties))
	for _, property := range sender.Properties {
		if property.IsSecret {
			senderProperties = append(senderProperties, model.SenderProperty{
				Name:     property.Name,
				Value:    "******",
				IsSecret: property.IsSecret,
			})
		} else {
			senderProperties = append(senderProperties, property)
		}
	}
	returnSender.Properties = senderProperties

	return returnSender
}
