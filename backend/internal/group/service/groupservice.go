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

// Package service provides the implementation for group management operations.
package service

import (
	"errors"
	"fmt"

	"github.com/asgardeo/thunder/internal/group/constants"
	"github.com/asgardeo/thunder/internal/group/model"
	"github.com/asgardeo/thunder/internal/group/store"
	ouconstants "github.com/asgardeo/thunder/internal/ou/constants"
	ouservice "github.com/asgardeo/thunder/internal/ou/service"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
	userservice "github.com/asgardeo/thunder/internal/user/service"
)

const loggerComponentName = "GroupMgtService"

// GroupServiceInterface defines the interface for the group service.
type GroupServiceInterface interface {
	GetGroupList(limit, offset int) (*model.GroupListResponse, *serviceerror.ServiceError)
	CreateGroup(request model.CreateGroupRequest) (*model.Group, *serviceerror.ServiceError)
	GetGroup(groupID string) (*model.Group, *serviceerror.ServiceError)
	UpdateGroup(groupID string, request model.UpdateGroupRequest) (*model.Group, *serviceerror.ServiceError)
	DeleteGroup(groupID string) *serviceerror.ServiceError
}

// GroupService is the default implementation of the GroupServiceInterface.
type GroupService struct{}

// GetGroupService creates a new instance of GroupService.
func GetGroupService() GroupServiceInterface {
	return &GroupService{}
}

// GetGroupList retrieves a list of groups. limit should be a positive integer & offset should be non-negative
// integer
func (gs *GroupService) GetGroupList(limit, offset int) (*model.GroupListResponse, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if err := validatePaginationParams(limit, offset); err != nil {
		return nil, err
	}

	totalCount, err := store.GetGroupListCount()
	if err != nil {
		logger.Error("Failed to get group count", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	groups, err := store.GetGroupList(limit, offset)
	if err != nil {
		logger.Error("Failed to list groups", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	groupBasics := make([]model.GroupBasic, 0, len(groups))
	for _, groupDAO := range groups {
		groupBasics = append(groupBasics, buildGroupBasic(groupDAO))
	}

	response := &model.GroupListResponse{
		TotalResults: totalCount,
		Groups:       groupBasics,
		StartIndex:   offset + 1,
		Count:        len(groupBasics),
		Links:        buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// CreateGroup creates a new group.
func (gs *GroupService) CreateGroup(request model.CreateGroupRequest) (*model.Group, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Creating group", log.String("name", request.Name))

	// Validate request
	if err := gs.validateCreateGroupRequest(request); err != nil {
		return nil, err
	}

	if err := gs.validateOU(request.OrganizationUnitID); err != nil {
		return nil, err
	}

	var userIDs []string
	var groupIDs []string
	for _, member := range request.Members {
		switch member.Type {
		case model.MemberTypeUser:
			userIDs = append(userIDs, member.ID)
		case model.MemberTypeGroup:
			groupIDs = append(groupIDs, member.ID)
		}
	}

	if err := gs.validateUserIDs(userIDs); err != nil {
		return nil, err
	}

	if err := gs.validateGroupIDs(groupIDs); err != nil {
		return nil, err
	}

	if err := store.CheckGroupNameConflictForCreate(request.Name, request.OrganizationUnitID); err != nil {
		if errors.Is(err, model.ErrGroupNameConflict) {
			logger.Debug("Group name conflict detected", log.String("name", request.Name))
			return nil, &constants.ErrorGroupNameConflict
		}
		logger.Error("Failed to check group name conflict", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	groupDAO := model.GroupDAO{
		ID:                 utils.GenerateUUID(),
		Name:               request.Name,
		Description:        request.Description,
		OrganizationUnitID: request.OrganizationUnitID,
		Members:            request.Members,
	}

	if err := store.CreateGroup(groupDAO); err != nil {
		logger.Error("Failed to create group", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	group := convertGroupDAOToGroup(groupDAO)
	logger.Debug("Successfully created group", log.String("id", groupDAO.ID), log.String("name", groupDAO.Name))
	return &group, nil
}

// GetGroup retrieves a specific group by its id.
func (gs *GroupService) GetGroup(groupID string) (*model.Group, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Retrieving group", log.String("id", groupID))

	if groupID == "" {
		return nil, &constants.ErrorMissingGroupID
	}

	groupDAO, err := store.GetGroup(groupID)
	if err != nil {
		if errors.Is(err, model.ErrGroupNotFound) {
			logger.Debug("Group not found", log.String("id", groupID))
			return nil, &constants.ErrorGroupNotFound
		}
		logger.Error("Failed to retrieve group", log.String("id", groupID), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	group := convertGroupDAOToGroup(groupDAO)
	logger.Debug("Successfully retrieved group", log.String("id", group.ID), log.String("name", group.Name))
	return &group, nil
}

// UpdateGroup updates an existing group.
func (gs *GroupService) UpdateGroup(
	groupID string, request model.UpdateGroupRequest) (*model.Group, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Updating group", log.String("id", groupID), log.String("name", request.Name))

	if groupID == "" {
		return nil, &constants.ErrorMissingGroupID
	}

	// Validate request
	if err := gs.validateUpdateGroupRequest(request); err != nil {
		return nil, err
	}

	// Get existing group to ensure it exists
	existingGroupDAO, err := store.GetGroup(groupID)
	if err != nil {
		if errors.Is(err, model.ErrGroupNotFound) {
			logger.Debug("Group not found", log.String("id", groupID))
			return nil, &constants.ErrorGroupNotFound
		}
		logger.Error("Failed to retrieve group", log.String("id", groupID), log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	existingGroup := convertGroupDAOToGroup(existingGroupDAO)
	updateOrganizationUnitID := existingGroupDAO.OrganizationUnitID

	if gs.isOrganizationUnitChanged(existingGroup, request) {
		if err := gs.validateOU(request.OrganizationUnitID); err != nil {
			return nil, err
		}
		updateOrganizationUnitID = request.OrganizationUnitID
	}

	var userIDs []string
	var groupIDs []string
	for _, member := range request.Members {
		switch member.Type {
		case model.MemberTypeUser:
			userIDs = append(userIDs, member.ID)
		case model.MemberTypeGroup:
			groupIDs = append(groupIDs, member.ID)
		}
	}

	if err := gs.validateUserIDs(userIDs); err != nil {
		return nil, err
	}

	if err := gs.validateGroupIDs(groupIDs); err != nil {
		return nil, err
	}

	if existingGroup.Name != request.Name || existingGroup.OrganizationUnitID != request.OrganizationUnitID {
		if err := store.CheckGroupNameConflictForUpdate(request.Name, request.OrganizationUnitID, groupID); err != nil {
			if errors.Is(err, model.ErrGroupNameConflict) {
				logger.Debug("Group name conflict detected during update", log.String("name", request.Name))
				return nil, &constants.ErrorGroupNameConflict
			}
			logger.Error("Failed to check group name conflict during update", log.Error(err))
			return nil, &constants.ErrorInternalServerError
		}
	}

	// Create updated group object
	updatedGroupDAO := model.GroupDAO{
		ID:                 existingGroup.ID,
		Name:               request.Name,
		Description:        request.Description,
		OrganizationUnitID: updateOrganizationUnitID,
		Members:            request.Members,
	}

	// Update group in the database
	if err := store.UpdateGroup(updatedGroupDAO); err != nil {
		logger.Error("Failed to update group", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	updatedGroup := convertGroupDAOToGroup(updatedGroupDAO)
	logger.Debug("Successfully updated group", log.String("id", groupID), log.String("name", request.Name))
	return &updatedGroup, nil
}

// DeleteGroup delete the specified group by its id.
func (gs *GroupService) DeleteGroup(groupID string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Deleting group", log.String("id", groupID))

	if groupID == "" {
		return &constants.ErrorMissingGroupID
	}

	// Check if group exists
	_, err := store.GetGroup(groupID)
	if err != nil {
		if errors.Is(err, model.ErrGroupNotFound) {
			logger.Debug("Group not found", log.String("id", groupID))
			return &constants.ErrorGroupNotFound
		}
		logger.Error("Failed to retrieve group", log.String("id", groupID), log.Error(err))
		return &constants.ErrorInternalServerError
	}

	// Delete the group
	if err := store.DeleteGroup(groupID); err != nil {
		logger.Error("Failed to delete group", log.String("id", groupID), log.Error(err))
		return &constants.ErrorInternalServerError
	}

	logger.Debug("Successfully deleted group", log.String("id", groupID))
	return nil
}

// validateCreateGroupRequest validates the create group request.
func (gs *GroupService) validateCreateGroupRequest(request model.CreateGroupRequest) *serviceerror.ServiceError {
	if request.Name == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	if request.OrganizationUnitID == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	for _, member := range request.Members {
		if member.Type != model.MemberTypeUser && member.Type != model.MemberTypeGroup {
			return &constants.ErrorInvalidRequestFormat
		}
		if member.ID == "" {
			return &constants.ErrorInvalidRequestFormat
		}
	}

	return nil
}

// validateUpdateGroupRequest validates the update group request.
func (gs *GroupService) validateUpdateGroupRequest(request model.UpdateGroupRequest) *serviceerror.ServiceError {
	if request.Name == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	if request.OrganizationUnitID == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	for _, member := range request.Members {
		if member.Type != model.MemberTypeUser && member.Type != model.MemberTypeGroup {
			return &constants.ErrorInvalidRequestFormat
		}
		if member.ID == "" {
			return &constants.ErrorInvalidRequestFormat
		}
	}

	return nil
}

// isOrganizationUnitChanged checks if the organization unit of the group has changed during an update.
func (gs *GroupService) isOrganizationUnitChanged(existingGroup model.Group, request model.UpdateGroupRequest) bool {
	return existingGroup.OrganizationUnitID != request.OrganizationUnitID
}

// validateOU validates that provided organization unit ID exist.
func (gs *GroupService) validateOU(ouID string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	ouService := ouservice.GetOrganizationUnitService()
	_, err := ouService.GetOrganizationUnit(ouID)
	if err != nil {
		if err.Code == ouconstants.ErrorOrganizationUnitNotFound.Code {
			return &constants.ErrorInvalidOUID
		} else {
			logger.Error("Failed to get organization unit", log.Any("error: ", err))
			return &constants.ErrorInternalServerError
		}
	}

	return nil
}

// validateUserIDs validates that all provided user IDs exist.
func (gs *GroupService) validateUserIDs(userIDs []string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	userService := userservice.GetUserService()
	invalidUserIDs, err := userService.ValidateUserIDs(userIDs)
	if err != nil {
		logger.Error("Failed to validate user IDs", log.Error(err))
		return &constants.ErrorInternalServerError
	}

	if len(invalidUserIDs) > 0 {
		logger.Debug("Invalid user IDs found", log.Any("invalidUserIDs", invalidUserIDs))
		return &constants.ErrorInvalidUserMemberID
	}

	return nil
}

// validateGroupIDs validates that all provided group IDs exist.
func (gs *GroupService) validateGroupIDs(groupIDs []string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	invalidGroupIDs, err := store.ValidateGroupIDs(groupIDs)
	if err != nil {
		logger.Error("Failed to validate group IDs", log.Error(err))
		return &constants.ErrorInternalServerError
	}

	if len(invalidGroupIDs) > 0 {
		logger.Debug("Invalid group IDs found", log.Any("invalidGroupIDs", invalidGroupIDs))
		return &constants.ErrorInvalidGroupMemberID
	}

	return nil
}

// convertGroupDAOToGroup constructs a model.Group from a model.GroupDAO.
func convertGroupDAOToGroup(groupDAO model.GroupDAO) model.Group {
	return model.Group(groupDAO)
}

// buildGroupBasic constructs a model.GroupBasic from a model.GroupBasicDAO.
func buildGroupBasic(groupDAO model.GroupBasicDAO) model.GroupBasic {
	return model.GroupBasic(groupDAO)
}

// validatePaginationParams validates pagination parameters.
func validatePaginationParams(limit, offset int) *serviceerror.ServiceError {
	if limit < 1 || limit > 100 {
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
			Href: fmt.Sprintf("/groups?offset=0&limit=%d", limit),
			Rel:  "first",
		})

		prevOffset := offset - limit
		if prevOffset < 0 {
			prevOffset = 0
		}
		links = append(links, model.Link{
			Href: fmt.Sprintf("/groups?offset=%d&limit=%d", prevOffset, limit),
			Rel:  "prev",
		})
	}

	if offset+limit < totalCount {
		nextOffset := offset + limit
		links = append(links, model.Link{
			Href: fmt.Sprintf("/groups?offset=%d&limit=%d", nextOffset, limit),
			Rel:  "next",
		})
	}

	lastPageOffset := ((totalCount - 1) / limit) * limit
	if offset < lastPageOffset {
		links = append(links, model.Link{
			Href: fmt.Sprintf("/groups?offset=%d&limit=%d", lastPageOffset, limit),
			Rel:  "last",
		})
	}

	return links
}
