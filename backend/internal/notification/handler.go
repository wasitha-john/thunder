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

package notification

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/asgardeo/thunder/internal/notification/common"
	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// NotificationSenderHandler handles HTTP requests for notification sender management
type NotificationSenderHandler struct {
	mgtService NotificationSenderMgtSvcInterface
}

// NewNotificationSenderHandler creates a new instance of NotificationHandler
func NewNotificationSenderHandler() *NotificationSenderHandler {
	return &NotificationSenderHandler{
		mgtService: getNotificationSenderMgtService(),
	}
}

// HandleSenderListRequest handles the request to list all notification senders
func (h *NotificationSenderHandler) HandleSenderListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationHandler"))

	senders, svcErr := h.mgtService.ListSenders()
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	senderResponses := make([]common.NotificationSenderResponse, 0, len(senders))
	for _, sender := range senders {
		senderResponses = append(senderResponses, getSenderResponseFromDTO(&sender))
	}

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(senderResponses); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleSenderCreateRequest handles the request to create a new notification sender
func (h *NotificationSenderHandler) HandleSenderCreateRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationHandler"))

	sender, err := sysutils.DecodeJSONBody[common.NotificationSenderRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        ErrorInvalidRequestFormat.Code,
			Message:     ErrorInvalidRequestFormat.Error,
			Description: "Failed to parse request body: " + err.Error(),
		}

		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	senderDTO := getDTOFromSenderRequest(sender)
	createdSender, svcErr := h.mgtService.CreateSender(*senderDTO)
	if svcErr != nil {
		if svcErr.Code == ErrorDuplicateSenderName.Code {
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

	senderResponse := getSenderResponseFromDTO(createdSender)

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(senderResponse); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleSenderGetRequest handles the request to get a notification sender by ID
func (h *NotificationSenderHandler) HandleSenderGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationHandler"))

	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        ErrorInvalidSenderID.Code,
			Message:     ErrorInvalidSenderID.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	sender, svcErr := h.mgtService.GetSender(id)
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}
	if sender == nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusNotFound)
		errResp := apierror.ErrorResponse{
			Code:        ErrorSenderNotFound.Code,
			Message:     ErrorSenderNotFound.Error,
			Description: ErrorSenderNotFound.ErrorDescription,
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	senderResponse := getSenderResponseFromDTO(sender)

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(senderResponse); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleSenderUpdateRequest handles the request to update a notification sender
func (h *NotificationSenderHandler) HandleSenderUpdateRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationHandler"))

	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        ErrorInvalidSenderID.Code,
			Message:     ErrorInvalidSenderID.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	sender, err := sysutils.DecodeJSONBody[common.NotificationSenderRequest](r)
	if err != nil {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)

		errResp := apierror.ErrorResponse{
			Code:        ErrorInvalidRequestFormat.Code,
			Message:     ErrorInvalidRequestFormat.Error,
			Description: "Failed to parse request body: " + err.Error(),
		}

		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
		}
		return
	}

	senderDTO := getDTOFromSenderRequest(sender)
	updatedSender, svcErr := h.mgtService.UpdateSender(id, *senderDTO)
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	senderResponse := getSenderResponseFromDTO(updatedSender)

	w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(senderResponse); err != nil {
		logger.Error("Error encoding response", log.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HandleSenderDeleteRequest handles the request to delete a notification sender
func (h *NotificationSenderHandler) HandleSenderDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NotificationHandler"))

	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		w.Header().Set(serverconst.ContentTypeHeaderName, serverconst.ContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		errResp := apierror.ErrorResponse{
			Code:        ErrorInvalidSenderID.Code,
			Message:     ErrorInvalidSenderID.Error,
			Description: "Sender ID is required",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			logger.Error("Error encoding error response", log.Error(err))
			http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
			return
		}
		return
	}

	svcErr := h.mgtService.DeleteSender(id)
	if svcErr != nil {
		h.handleError(w, logger, svcErr)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleError handles service errors and returns appropriate HTTP responses.
func (h *NotificationSenderHandler) handleError(w http.ResponseWriter, logger *log.Logger,
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
		case ErrorSenderNotFound.Code:
			statusCode = http.StatusNotFound
		case ErrorDuplicateSenderName.Code:
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

// getDTOFromSenderRequest sanitizes the sender request and converts it to a NotificationSenderDTO.
func getDTOFromSenderRequest(sender *common.NotificationSenderRequest) *common.NotificationSenderDTO {
	name := sysutils.SanitizeString(sender.Name)
	description := sysutils.SanitizeString(sender.Description)
	typeStr := sysutils.SanitizeString(string(sender.Type))
	providerStr := sysutils.SanitizeString(sender.Provider)

	// Sanitize properties
	properties := make([]common.SenderProperty, 0, len(sender.Properties))
	for _, prop := range sender.Properties {
		properties = append(properties, common.SenderProperty{
			Name:     sysutils.SanitizeString(prop.Name),
			Value:    sysutils.SanitizeString(prop.Value),
			IsSecret: prop.IsSecret,
		})
	}

	senderDTO := common.NotificationSenderDTO{
		Name:        name,
		Description: description,
		Type:        common.NotificationSenderType(typeStr),
		Provider:    common.MessageProviderType(providerStr),
		Properties:  properties,
	}
	return &senderDTO
}

// getSenderResponseFromDTO converts a NotificationSenderDTO to a response object, masking secret properties.
func getSenderResponseFromDTO(sender *common.NotificationSenderDTO) common.NotificationSenderResponse {
	returnSender := common.NotificationSenderResponse{
		ID:          sender.ID,
		Name:        sender.Name,
		Description: sender.Description,
		Type:        sender.Type,
		Provider:    sender.Provider,
	}

	// Mask secret properties in the response.
	senderProperties := make([]common.SenderProperty, 0, len(sender.Properties))
	for _, property := range sender.Properties {
		if property.IsSecret {
			senderProperties = append(senderProperties, common.SenderProperty{
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
