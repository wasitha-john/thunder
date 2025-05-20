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

// Package handler provides the implementation for user management operations.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/user/model"
	userprovider "github.com/asgardeo/thunder/internal/user/provider"
)

// UserHandler is the handler for user management operations.
//
// @title          User Management API
// @version        1.0
// @description    This API is used to manage users.
//
// @license.name   Apache 2.0
// @license.url    http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host           localhost:8090
// @BasePath       /
type UserHandler struct {
}

// HandleUserPostRequest handles the user request.
//
// @Summary      Create an user
// @Description  Creates a new user with the provided details.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        user  body  model.User  true  "User data"
// @Success      201  {object}  model.User
// @Failure      400  {string}  "Bad Request: The request body is malformed or contains invalid data."
// @Failure      500  {string}  "Internal Server Error"
// @Router       /users [post]
func (ah *UserHandler) HandleUserPostRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserHandler"))

	var userInCreationRequest model.User
	if err := json.NewDecoder(r.Body).Decode(&userInCreationRequest); err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}

	// Create the user using the user service.
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()
	createdUser, err := userService.CreateUser(&userInCreationRequest)
	if err != nil {
		if errors.Is(err, model.ErrBadAttributesInRequest) {
			http.Error(w, "Bad Request: The attributes element is malformed or contains invalid data.", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(createdUser)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the user creation response.
	logger.Debug("User POST response sent", log.String("user id", createdUser.ID))
}

// HandleUserListRequest handles the user request.
//
// @Summary      List users
// @Description  Retrieve a list of all users.
// @Tags         users
// @Accept       json
// @Produce      json
// @Success      200  {array}   model.User
// @Failure      500  {string}  "Internal Server Error"
// @Router       /users [get]
func (ah *UserHandler) HandleUserListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserHandler"))

	// Get the user list using the user service.
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()
	users, err := userService.GetUserList()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the user response.
	logger.Debug("User GET (list) response sent")
}

// HandleUserGetRequest handles the user request.
//
// @Summary      Get an user by id
// @Description  Retrieve a specific user using its id.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "User id"
// @Success      200  {object}  model.User
// @Failure      400  {string}  "Bad Request: Missing user id."
// @Failure      404  {string}  "Not Found: The user with the specified id does not exist."
// @Failure      500  {string}  "Internal Server Error"
// @Router       /users/{id} [get]
func (ah *UserHandler) HandleUserGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/users/")
	if id == "" {
		http.Error(w, "Bad Request: Missing user id.", http.StatusBadRequest)
		return
	}

	// Get the user using the user service.
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()
	user, err := userService.GetUser(id)
	if err != nil {
		if errors.Is(err, model.ErrUserNotFound) {
			http.Error(w, "Not Found: The user with the specified id does not exist.", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the user response.
	logger.Debug("User GET response sent", log.String("user id", id))
}

// HandleUserPutRequest handles the user request.
//
// @Summary      Update an user
// @Description  Update the details of an existing user.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id           path   string            true  "User id"
// @Param        user  body   model.User  true  "Updated user data"
// @Success      200  {object}  model.User
// @Failure      400  {string}  "Bad Request: Missing user id."
// @Failure      404  {string}  "Not Found: The user with the specified id does not exist."
// @Failure      404  {string}  "Bad Request: The request body is malformed or contains invalid data."
// @Failure      500  {string}  "Internal Server Error"
// @Router       /users/{id} [put]
func (ah *UserHandler) HandleUserPutRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/users/")
	if id == "" {
		http.Error(w, "Bad Request: Missing user id.", http.StatusBadRequest)
		return
	}

	var updatedUser model.User
	if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}
	updatedUser.ID = id

	// Update the user using the user service.
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()
	user, err := userService.UpdateUser(id, &updatedUser)
	if err != nil {
		if errors.Is(err, model.ErrUserNotFound) {
			http.Error(w, "Not Found: The user with the specified id does not exist.", http.StatusNotFound)
		} else if errors.Is(err, model.ErrBadAttributesInRequest) {
			http.Error(w, "Bad Request: The attributes element is malformed or contains invalid data.", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the user response.
	logger.Debug("User PUT response sent", log.String("user id", id))
}

// HandleUserDeleteRequest handles the user request.
//
// @Summary      Delete an user
// @Description  Delete an user using its id.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id   path   string  true  "User id"
// @Success      204
// @Failure      400  {string}  "Bad Request: Missing user id."
// @Failure      500  {string}  "Internal Server Error"
// @Router       /users/{id} [delete]
func (ah *UserHandler) HandleUserDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "UserHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/users/")
	if id == "" {
		http.Error(w, "Bad Request: Missing user id.", http.StatusBadRequest)
		return
	}

	// Delete the user using the user service.
	userProvider := userprovider.NewUserProvider()
	userService := userProvider.GetUserService()
	err := userService.DeleteUser(id)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	// Log the user response.
	logger.Debug("User DELETE response sent", log.String("user id", id))
}
