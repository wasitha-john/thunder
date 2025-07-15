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

	ouID, err := gs.resolveOU(request.Parent)
	if err != nil {
		return nil, err
	}

	logger.Debug("Resolved OU for new group", log.String("ouID", *ouID))

	if err := gs.validateUserIDs(request.Users); err != nil {
		return nil, err
	}

	// Check if group with same name already exists under the same parent
	if err := store.CheckGroupNameConflictForCreate(request.Name, request.Parent); err != nil {
		if errors.Is(err, model.ErrGroupNameConflict) {
			logger.Debug("Group name conflict detected", log.String("name", request.Name))
			return nil, &constants.ErrorGroupNameConflict
		}
		logger.Error("Failed to check group name conflict", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	var parentGroupID *string
	if request.Parent.Type == model.ParentTypeGroup {
		parentGroupID = &request.Parent.ID
	}

	groupDAO := model.GroupDAO{
		ID:          utils.GenerateUUID(),
		Name:        request.Name,
		Description: request.Description,
		Parent:      parentGroupID,
		OU:          *ouID,
		Users:       request.Users,
		Groups:      []string{},
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
	updateOU := existingGroupDAO.OU

	if gs.isParentChanged(existingGroup, request) {
		ouID, err := gs.resolveOU(request.Parent)
		if err != nil {
			return nil, err
		}
		logger.Debug("Resolved OU for group update", log.String("ouID", *ouID))
		updateOU = *ouID
	}

	if err := gs.validateUserIDs(request.Users); err != nil {
		return nil, err
	}

	// Check for duplicate name under the same parent (only if name or parent changed)
	if existingGroup.Name != request.Name || existingGroup.Parent.ID != request.Parent.ID ||
		existingGroup.Parent.Type != request.Parent.Type {
		if err := store.CheckGroupNameConflictForUpdate(request.Name, request.Parent, groupID); err != nil {
			if errors.Is(err, model.ErrGroupNameConflict) {
				logger.Debug("Group name conflict detected during update", log.String("name", request.Name))
				return nil, &constants.ErrorGroupNameConflict
			}
			logger.Error("Failed to check group name conflict during update", log.Error(err))
			return nil, &constants.ErrorInternalServerError
		}
	}

	var parentGroupID *string
	if request.Parent.Type == model.ParentTypeGroup {
		parentGroupID = &request.Parent.ID
	}

	// Create updated group object
	updatedGroupDAO := model.GroupDAO{
		ID:          existingGroup.ID,
		Name:        request.Name,
		Description: request.Description,
		Parent:      parentGroupID,
		OU:          updateOU,
		Users:       request.Users,
		Groups:      request.Groups,
	}

	// Update group in the database
	if err := store.UpdateGroup(updatedGroupDAO); err != nil {
		if errors.Is(err, model.ErrParentNotFound) {
			logger.Debug("Parent not found during group update", log.String("parentID", request.Parent.ID))
			return nil, &constants.ErrorParentNotFound
		}
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

	// Check if group can be deleted (no child groups)
	if err := gs.validateForDeleteGroup(groupID); err != nil {
		return err
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

	if request.Parent.Type == "" || request.Parent.ID == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	// Use ParentType constants for validation
	if request.Parent.Type != model.ParentTypeGroup && request.Parent.Type != model.ParentTypeOrganizationUnit {
		return &constants.ErrorInvalidRequestFormat
	}

	return nil
}

// validateUpdateGroupRequest validates the update group request.
func (gs *GroupService) validateUpdateGroupRequest(request model.UpdateGroupRequest) *serviceerror.ServiceError {
	if request.Name == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	if request.Parent.Type == "" || request.Parent.ID == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	// Use ParentType constants for validation
	if request.Parent.Type != model.ParentTypeGroup && request.Parent.Type != model.ParentTypeOrganizationUnit {
		return &constants.ErrorInvalidRequestFormat
	}

	return nil
}

// isParentChanged checks if the parent of the group has changed during an update.
func (gs *GroupService) isParentChanged(existingGroup model.Group, request model.UpdateGroupRequest) bool {
	return existingGroup.Parent.ID != request.Parent.ID || existingGroup.Parent.Type != request.Parent.Type
}

// resolveOU resolves the organization unit ID from the parent and validates its existence.
func (gs *GroupService) resolveOU(parent model.Parent) (*string, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	switch parent.Type {
	case model.ParentTypeGroup:
		parentGroup, err := store.GetGroup(parent.ID)
		if err != nil {
			if errors.Is(err, model.ErrGroupNotFound) {
				logger.Debug("Parent group not found", log.String("parentID", parent.ID))
				return nil, &constants.ErrorParentNotFound
			}
			logger.Error("Failed to check parent group existence", log.String("parentID", parent.ID), log.Error(err))
			return nil, &constants.ErrorInternalServerError
		}
		return &parentGroup.OU, nil
	case model.ParentTypeOrganizationUnit:
		// TODO: Add validation for organization unit existence
		logger.Debug("Organization unit validation not implemented", log.String("parentID", parent.ID))
		return &parent.ID, nil
	default:
		return nil, &constants.ErrorInvalidRequestFormat
	}
}

// validateForDeleteGroup checks if the group can be deleted.
func (gs *GroupService) validateForDeleteGroup(groupID string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	childGroups, err := store.GetChildGroups(groupID)
	if err != nil {
		logger.Error("Failed to check for child groups", log.String("groupID", groupID), log.Error(err))
		return &constants.ErrorInternalServerError
	}

	if childGroups != nil && len(*childGroups) > 0 {
		logger.Debug("Cannot delete group with child groups", log.String("groupID", groupID),
			log.Int("childCount", len(*childGroups)))
		return &constants.ErrorCannotDeleteGroup
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
		return &constants.ErrorInvalidUserID
	}

	return nil
}

// convertGroupDAOToGroup constructs a model.Group from a model.GroupDAO.
func convertGroupDAOToGroup(groupDAO model.GroupDAO) model.Group {
	parent := buildParent(groupDAO.Parent, groupDAO.OU)
	group := model.Group{
		ID:          groupDAO.ID,
		Name:        groupDAO.Name,
		Description: groupDAO.Description,
		Parent:      parent,
		Users:       groupDAO.Users,
		Groups:      groupDAO.Groups,
	}
	return group
}

// buildGroupBasic constructs a model.GroupBasic from a model.GroupDAO.
func buildGroupBasic(groupDAO model.GroupBasicDAO) model.GroupBasic {
	parent := buildParent(groupDAO.Parent, groupDAO.OU)
	return model.GroupBasic{
		ID:          groupDAO.ID,
		Name:        groupDAO.Name,
		Description: groupDAO.Description,
		Parent:      parent,
	}
}

func buildParent(parentID *string, ouID string) model.Parent {
	var parent model.Parent
	if parentID == nil {
		parent = model.Parent{
			Type: model.ParentTypeOrganizationUnit,
			ID:   ouID,
		}
	} else {
		parent = model.Parent{
			Type: model.ParentTypeGroup,
			ID:   *parentID,
		}
	}
	return parent
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
