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

// Package service provides the implementation for user schema management operations.
package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
	"github.com/asgardeo/thunder/internal/userschema/constants"
	"github.com/asgardeo/thunder/internal/userschema/model"
	"github.com/asgardeo/thunder/internal/userschema/store"
)

const userSchemaLoggerComponentName = "UserSchemaService"

// UserSchemaServiceInterface defines the interface for the user schema service.
type UserSchemaServiceInterface interface {
	GetUserSchemaList(limit, offset int) (*model.UserSchemaListResponse, *serviceerror.ServiceError)
	CreateUserSchema(request model.CreateUserSchemaRequest) (*model.UserSchema, *serviceerror.ServiceError)
	GetUserSchema(schemaID string) (*model.UserSchema, *serviceerror.ServiceError)
	UpdateUserSchema(schemaID string, request model.UpdateUserSchemaRequest) (
		*model.UserSchema, *serviceerror.ServiceError)
	DeleteUserSchema(schemaID string) *serviceerror.ServiceError
	ValidateUser(userType string, userAttributes json.RawMessage) (bool, *serviceerror.ServiceError)
	ValidateUserUniqueness(userType string, userAttributes json.RawMessage,
		identifyUser func(map[string]interface{}) (*string, error)) (bool, *serviceerror.ServiceError)
}

// UserSchemaService is the default implementation of the UserSchemaServiceInterface.
type UserSchemaService struct{}

// GetUserSchemaService creates a new instance of UserSchemaService.
func GetUserSchemaService() UserSchemaServiceInterface {
	return &UserSchemaService{}
}

// GetUserSchemaList lists the user schemas with pagination.
func (us *UserSchemaService) GetUserSchemaList(limit, offset int) (
	*model.UserSchemaListResponse, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if err := validatePaginationParams(limit, offset); err != nil {
		return nil, err
	}

	totalCount, err := store.GetUserSchemaListCount()
	if err != nil {
		return nil, logAndReturnServerError(logger, "Failed to get user schema list count", err)
	}

	userSchemas, err := store.GetUserSchemaList(limit, offset)
	if err != nil {
		return nil, logAndReturnServerError(logger, "Failed to get user schema list", err)
	}

	response := &model.UserSchemaListResponse{
		TotalResults: totalCount,
		StartIndex:   offset + 1,
		Count:        len(userSchemas),
		Schemas:      userSchemas,
		Links:        buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// CreateUserSchema creates a new user schema.
func (us *UserSchemaService) CreateUserSchema(request model.CreateUserSchemaRequest) (
	*model.UserSchema, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if request.Name == "" {
		return nil, invalidSchemaRequestError("user schema name must not be empty")
	}

	if len(request.Schema) == 0 {
		return nil, invalidSchemaRequestError("schema definition must not be empty")
	}

	_, err := model.CompileUserSchema(request.Schema)
	if err != nil {
		logger.Debug("Provided user schema failed compilation", log.String("name", request.Name), log.Error(err))
		return nil, invalidSchemaRequestError(err.Error())
	}

	_, err = store.GetUserSchemaByName(request.Name)
	if err == nil {
		return nil, &constants.ErrorUserSchemaNameConflict
	} else if !errors.Is(err, constants.ErrUserSchemaNotFound) {
		return nil, logAndReturnServerError(logger, "Failed to check existing user schema", err)
	}

	schemaID := utils.GenerateUUID()

	userSchema := model.UserSchema{
		ID:     schemaID,
		Name:   request.Name,
		Schema: request.Schema,
	}

	if err := store.CreateUserSchema(userSchema); err != nil {
		return nil, logAndReturnServerError(logger, "Failed to create user schema", err)
	}

	return &userSchema, nil
}

// GetUserSchema retrieves a user schema by its ID.
func (us *UserSchemaService) GetUserSchema(schemaID string) (*model.UserSchema, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if schemaID == "" {
		return nil, invalidSchemaRequestError("schema id must not be empty")
	}

	userSchema, err := store.GetUserSchemaByID(schemaID)
	if err != nil {
		if errors.Is(err, constants.ErrUserSchemaNotFound) {
			return nil, &constants.ErrorUserSchemaNotFound
		}
		return nil, logAndReturnServerError(logger, "Failed to get user schema", err)
	}

	return &userSchema, nil
}

// UpdateUserSchema updates a user schema by its ID.
func (us *UserSchemaService) UpdateUserSchema(schemaID string, request model.UpdateUserSchemaRequest) (
	*model.UserSchema, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if schemaID == "" {
		return nil, invalidSchemaRequestError("schema id must not be empty")
	}

	if request.Name == "" {
		return nil, invalidSchemaRequestError("user schema name must not be empty")
	}

	if len(request.Schema) == 0 {
		return nil, invalidSchemaRequestError("schema definition must not be empty")
	}

	_, err := model.CompileUserSchema(request.Schema)
	if err != nil {
		logger.Debug("Provided user schema failed compilation", log.String("id", schemaID), log.Error(err))
		return nil, invalidSchemaRequestError(err.Error())
	}

	existingSchema, err := store.GetUserSchemaByID(schemaID)
	if err != nil {
		if errors.Is(err, constants.ErrUserSchemaNotFound) {
			return nil, &constants.ErrorUserSchemaNotFound
		}
		return nil, logAndReturnServerError(logger, "Failed to get existing user schema", err)
	}

	if request.Name != existingSchema.Name {
		_, err := store.GetUserSchemaByName(request.Name)
		if err == nil {
			return nil, &constants.ErrorUserSchemaNameConflict
		} else if !errors.Is(err, constants.ErrUserSchemaNotFound) {
			return nil, logAndReturnServerError(logger, "Failed to check existing user schema", err)
		}
	}

	userSchema := model.UserSchema{
		ID:     schemaID,
		Name:   request.Name,
		Schema: request.Schema,
	}

	if err := store.UpdateUserSchemaByID(schemaID, userSchema); err != nil {
		return nil, logAndReturnServerError(logger, "Failed to update user schema", err)
	}

	return &userSchema, nil
}

// DeleteUserSchema deletes a user schema by its ID.
func (us *UserSchemaService) DeleteUserSchema(schemaID string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if schemaID == "" {
		return invalidSchemaRequestError("schema id must not be empty")
	}

	if err := store.DeleteUserSchemaByID(schemaID); err != nil {
		return logAndReturnServerError(logger, "Failed to delete user schema", err)
	}

	return nil
}

// validatePaginationParams validates the limit and offset parameters.
func validatePaginationParams(limit, offset int) *serviceerror.ServiceError {
	if limit < 0 {
		return &constants.ErrorInvalidLimit
	}
	if offset < 0 {
		return &constants.ErrorInvalidOffset
	}
	return nil
}

// buildPaginationLinks builds pagination links for the response.
func buildPaginationLinks(limit, offset, totalCount int) []model.Link {
	links := make([]model.Link, 0)

	if offset > 0 {
		links = append(links, model.Link{
			Href: fmt.Sprintf("/user-schemas?offset=0&limit=%d", limit),
			Rel:  "first",
		})

		prevOffset := offset - limit
		if prevOffset < 0 {
			prevOffset = 0
		}
		links = append(links, model.Link{
			Href: fmt.Sprintf("/user-schemas?offset=%d&limit=%d", prevOffset, limit),
			Rel:  "prev",
		})
	}

	if offset+limit < totalCount {
		nextOffset := offset + limit
		links = append(links, model.Link{
			Href: fmt.Sprintf("/user-schemas?offset=%d&limit=%d", nextOffset, limit),
			Rel:  "next",
		})
	}

	lastPageOffset := ((totalCount - 1) / limit) * limit
	if offset < lastPageOffset {
		links = append(links, model.Link{
			Href: fmt.Sprintf("/user-schemas?offset=%d&limit=%d", lastPageOffset, limit),
			Rel:  "last",
		})
	}

	return links
}

// logAndReturnServerError logs the error and returns a server error.
func logAndReturnServerError(
	logger *log.Logger,
	message string,
	err error,
) *serviceerror.ServiceError {
	logger.Error(message, log.Error(err))
	return &constants.ErrorInternalServerError
}

func invalidSchemaRequestError(detail string) *serviceerror.ServiceError {
	err := constants.ErrorInvalidUserSchemaRequest
	errorDescription := err.ErrorDescription
	if detail != "" {
		errorDescription = fmt.Sprintf("%s: %s", err.ErrorDescription, detail)
	}
	return &serviceerror.ServiceError{
		Code:             err.Code,
		Type:             err.Type,
		Error:            err.Error,
		ErrorDescription: errorDescription,
	}
}

func (us *UserSchemaService) getCompiledSchemaForUserType(
	userType string,
	logger *log.Logger,
) (*model.Schema, error) {
	if userType == "" {
		return nil, constants.ErrUserSchemaNotFound
	}

	userSchema, err := store.GetUserSchemaByName(userType)
	if err != nil {
		return nil, err
	}

	compiled, err := model.CompileUserSchema(userSchema.Schema)
	if err != nil {
		logger.Error("Failed to compile stored user schema", log.String("userType", userType), log.Error(err))
		return nil, fmt.Errorf("failed to compile stored user schema: %w", err)
	}

	return compiled, nil
}

// ValidateUser validates user attributes against the user schema for the given user type.
func (us *UserSchemaService) ValidateUser(
	userType string, userAttributes json.RawMessage,
) (bool, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if userType == "" {
		logger.Debug("User type is empty, skipping schema validation")
		return true, nil
	}

	compiledSchema, err := us.getCompiledSchemaForUserType(userType, logger)
	if err != nil {
		if errors.Is(err, constants.ErrUserSchemaNotFound) {
			logger.Debug("No schema found for user type, skipping validation", log.String("userType", userType))
			return true, nil
		}
		return false, logAndReturnServerError(logger, "Failed to load user schema", err)
	}

	isValid, err := compiledSchema.Validate(userAttributes, logger)
	if err != nil {
		return false, logAndReturnServerError(logger, "Failed to validate user attributes against schema", err)
	}
	if !isValid {
		logger.Debug("Schema validation failed", log.String("userType", userType))
		return false, nil
	}

	logger.Debug("Schema validation successful", log.String("userType", userType))
	return true, nil
}

// ValidateUserUniqueness validates the uniqueness constraints of user attributes.
func (us *UserSchemaService) ValidateUserUniqueness(
	userType string,
	userAttributes json.RawMessage,
	identifyUser func(map[string]interface{}) (*string, error),
) (bool, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, userSchemaLoggerComponentName))

	if userType == "" {
		return true, nil
	}

	compiledSchema, err := us.getCompiledSchemaForUserType(userType, logger)
	if err != nil {
		if errors.Is(err, constants.ErrUserSchemaNotFound) {
			return true, nil
		}
		return false, logAndReturnServerError(logger, "Failed to load user schema", err)
	}

	if len(userAttributes) == 0 {
		return true, nil
	}

	var userAttrs map[string]interface{}
	if err := json.Unmarshal(userAttributes, &userAttrs); err != nil {
		return false, logAndReturnServerError(logger, "Failed to unmarshal user attributes", err)
	}

	isValid, err := compiledSchema.ValidateUniqueness(userAttrs, identifyUser, logger)
	if err != nil {
		return false, logAndReturnServerError(logger, "Failed during uniqueness validation", err)
	}
	if !isValid {
		logger.Debug("User attribute failed uniqueness validation", log.String("userType", userType))
		return false, nil
	}

	return true, nil
}
