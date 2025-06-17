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

// Package service provides the implementation for user management operations.
package service

import (
	"encoding/json"
	"errors"

	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
	"github.com/asgardeo/thunder/internal/user/model"
	"github.com/asgardeo/thunder/internal/user/store"
)

// UserServiceInterface defines the interface for the user service.
type UserServiceInterface interface {
	CreateUser(user *model.User) (*model.User, error)
	GetUserList() ([]model.User, error)
	GetUser(userID string) (*model.User, error)
	UpdateUser(userID string, user *model.User) (*model.User, error)
	DeleteUser(userID string) error
	IdentityUser(attrName, attrValue string) (*string, error)
	VerifyUser(userID, credType, credValue string) (*model.User, error)
}

// UserService is the default implementation of the UserServiceInterface.
type UserService struct{}

// GetUserService creates a new instance of UserService.
func GetUserService() UserServiceInterface {
	return &UserService{}
}

// CreateUser creates the user.
func (as *UserService) CreateUser(user *model.User) (*model.User, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserService"))

	user.ID = utils.GenerateUUID()

	credentials, err := extractCredentials(user)
	if err != nil {
		logger.Error("Failed to create user DTO", log.Error(err))
		return nil, err
	}

	// Create the user in the database.
	err = store.CreateUser(*user, *credentials)
	if err != nil {
		logger.Error("Failed to create user", log.Error(err))
		return nil, err
	}
	return user, nil
}

// extractCredentials extracts the credentials from the user attributes and returns a Credentials object.
func extractCredentials(user *model.User) (*model.Credentials, error) {
	var attrsMap map[string]interface{}
	if err := json.Unmarshal(user.Attributes, &attrsMap); err != nil {
		return nil, err
	}

	if pw, ok := attrsMap["password"].(string); ok {
		// Generate a salt
		pwSalt, err := utils.GenerateSalt()
		if err != nil {
			return nil, err
		}

		// Hash the password with the salt
		pwHash, err := utils.HashStringWithSalt(pw, pwSalt)
		if err != nil {
			return nil, err
		}

		delete(attrsMap, "password")
		updatedAttrs, err := json.Marshal(attrsMap)
		if err != nil {
			return nil, err
		}
		user.Attributes = updatedAttrs

		credentials := model.Credentials{
			CredentialType: "password",
			StorageType:    "hash",
			StorageAlgo:    "SHA-256",
			Value:          pwHash,
			Salt:           pwSalt,
		}

		return &credentials, nil
	}

	return &model.Credentials{}, nil
}

// GetUserList list the users.
func (as *UserService) GetUserList() ([]model.User, error) {
	users, err := store.GetUserList()
	if err != nil {
		return nil, err
	}

	return users, nil
}

// GetUser get the user for given user id.
func (as *UserService) GetUser(userID string) (*model.User, error) {
	if userID == "" {
		return nil, errors.New("user ID is empty")
	}

	user, err := store.GetUser(userID)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUser update the user for given user id.
func (as *UserService) UpdateUser(userID string, user *model.User) (*model.User, error) {
	if userID == "" {
		return nil, errors.New("user ID is empty")
	}

	err := store.UpdateUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteUser delete the user for given user id.
func (as *UserService) DeleteUser(userID string) error {
	if userID == "" {
		return errors.New("user ID is empty")
	}

	err := store.DeleteUser(userID)
	if err != nil {
		return err
	}

	return nil
}

// IdentityUser identify user with the given attributes.
func (as *UserService) IdentityUser(attrName, attrValue string) (*string, error) {
	if attrName == "" {
		return nil, errors.New("attribute name is empty")
	}

	if attrValue == "" {
		return nil, errors.New("attribute value is empty")
	}

	userID, err := store.IdentifyUser(attrName, attrValue)
	if err != nil {
		return nil, err
	}

	return userID, nil
}

// VerifyUser validate the specified user with the given credentials.
func (as *UserService) VerifyUser(userID, credType, credValue string) (*model.User, error) {
	if userID == "" {
		return nil, errors.New("user ID is empty")
	}

	if credType == "" {
		return nil, errors.New("credential type is empty")
	}

	if credValue == "" {
		return nil, errors.New("credential value is empty")
	}

	user, credentials, err := store.VerifyUser(userID)
	if err != nil {
		return nil, err
	}

	// Fix the comparison to check for an empty Credentials struct instead of nil.
	if credentials == (model.Credentials{}) {
		return nil, errors.New("credentials not found for user " + userID)
	}
	if credentials.CredentialType == "" || credentials.Value == "" || credentials.Salt == "" {
		return nil, errors.New("incomplete credentials for user " + userID)
	}

	hashToCompare, err := utils.HashStringWithSalt(credValue, credentials.Salt)
	if err != nil {
		return nil, errors.New("failed to hash credential value")
	}
	if credentials.CredentialType != credType {
		return nil, errors.New("invalid credential type for user " + userID)
	}
	if credentials.Value != hashToCompare {
		return nil, errors.New("invalid credentials for user " + userID)
	}

	return &user, nil
}
