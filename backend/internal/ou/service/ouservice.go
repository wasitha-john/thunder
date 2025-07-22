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

// Package service provides the implementation for organization unit management operations.
package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/asgardeo/thunder/internal/ou/constants"
	"github.com/asgardeo/thunder/internal/ou/model"
	"github.com/asgardeo/thunder/internal/ou/store"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

const loggerComponentName = "OrganizationUnitService"

// OrganizationUnitServiceInterface defines the interface for organization unit service operations.
type OrganizationUnitServiceInterface interface {
	GetOrganizationUnitList(limit, offset int) (*model.OrganizationUnitListResponse, *serviceerror.ServiceError)
	CreateOrganizationUnit(
		request model.OrganizationUnitRequest,
	) (model.OrganizationUnit, *serviceerror.ServiceError)
	GetOrganizationUnit(id string) (model.OrganizationUnit, *serviceerror.ServiceError)
	IsOrganizationUnitExists(id string) (bool, *serviceerror.ServiceError)
	UpdateOrganizationUnit(
		id string, request model.OrganizationUnitRequest,
	) (model.OrganizationUnit, *serviceerror.ServiceError)
	DeleteOrganizationUnit(id string) *serviceerror.ServiceError
	GetOrganizationUnitChildren(
		id string, limit, offset int,
	) (*model.OrganizationUnitListResponse, *serviceerror.ServiceError)
	GetOrganizationUnitUsers(id string, limit, offset int) (*model.UserListResponse, *serviceerror.ServiceError)
	GetOrganizationUnitGroups(id string, limit, offset int) (*model.GroupListResponse, *serviceerror.ServiceError)
}

// OrganizationUnitService provides organization unit management operations.
type OrganizationUnitService struct{}

// GetOrganizationUnitService creates a new instance of OrganizationUnitService.
func GetOrganizationUnitService() OrganizationUnitServiceInterface {
	return &OrganizationUnitService{}
}

// GetOrganizationUnitList retrieves a list of organization units.
// limit should be a positive integer and offset should be non-negative.
func (ous *OrganizationUnitService) GetOrganizationUnitList(limit, offset int) (
	*model.OrganizationUnitListResponse, *serviceerror.ServiceError,
) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	if err := validatePaginationParams(limit, offset); err != nil {
		return nil, err
	}

	totalCount, err := store.GetOrganizationUnitListCount()
	if err != nil {
		logger.Error("Failed to get organization unit count", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	ouList, err := store.GetOrganizationUnitList(limit, offset)
	if err != nil {
		logger.Error("Failed to list organization units", log.Error(err))
		return nil, &constants.ErrorInternalServerError
	}

	response := &model.OrganizationUnitListResponse{
		TotalResults:      totalCount,
		OrganizationUnits: ouList,
		StartIndex:        offset + 1,
		Count:             len(ouList),
		Links:             buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// CreateOrganizationUnit creates a new organization unit.
func (ous *OrganizationUnitService) CreateOrganizationUnit(
	request model.OrganizationUnitRequest,
) (model.OrganizationUnit, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Creating organization unit", log.String("name", request.Name))

	if err := ous.validateOUName(request.Name); err != nil {
		return model.OrganizationUnit{}, err
	}

	if err := ous.validateOUHandle(request.Handle); err != nil {
		return model.OrganizationUnit{}, err
	}

	if request.Parent != nil {
		exists, err := store.IsOrganizationUnitExists(*request.Parent)
		if err != nil {
			logger.Error("Failed to check parent organization unit existence", log.Error(err))
			return model.OrganizationUnit{}, &constants.ErrorInternalServerError
		}
		if !exists {
			return model.OrganizationUnit{}, &constants.ErrorParentOrganizationUnitNotFound
		}
	}

	conflict, err := store.CheckOrganizationUnitNameConflict(request.Name, request.Parent)
	if err != nil {
		logger.Error("Failed to check organization unit name conflict", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}
	if conflict {
		return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitNameConflict
	}

	handleConflict, err := store.CheckOrganizationUnitHandleConflict(request.Handle, request.Parent)
	if err != nil {
		logger.Error("Failed to check organization unit handle conflict", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}
	if handleConflict {
		return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitHandleConflict
	}

	ouID := utils.GenerateUUID()
	ou := model.OrganizationUnit{
		ID:          ouID,
		Handle:      request.Handle,
		Name:        request.Name,
		Description: request.Description,
		Parent:      request.Parent,
	}

	err = store.CreateOrganizationUnit(ou)
	if err != nil {
		logger.Error("Failed to create organization unit", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}

	logger.Debug("Successfully created organization unit", log.String("ouID", ouID))

	return ou, nil
}

// GetOrganizationUnit retrieves an organization unit by ID.
func (ous *OrganizationUnitService) GetOrganizationUnit(
	id string,
) (model.OrganizationUnit, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Getting organization unit", log.String("ouID", id))

	ou, err := store.GetOrganizationUnit(id)
	if err != nil {
		if errors.Is(err, constants.ErrOrganizationUnitNotFound) {
			return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitNotFound
		}
		logger.Error("Failed to get organization unit", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}

	return ou, nil
}

// IsOrganizationUnitExists checks if an organization unit exists by ID.
func (ous *OrganizationUnitService) IsOrganizationUnitExists(id string) (bool, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Checking if organization unit exists", log.String("ouID", id))

	exists, err := store.IsOrganizationUnitExists(id)
	if err != nil {
		logger.Error("Failed to check organization unit existence", log.Error(err))
		return false, &constants.ErrorInternalServerError
	}

	return exists, nil
}

// UpdateOrganizationUnit updates an organization unit.
func (ous *OrganizationUnitService) UpdateOrganizationUnit(
	id string, request model.OrganizationUnitRequest,
) (model.OrganizationUnit, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Updating organization unit", log.String("ouID", id))

	if err := ous.validateOUName(request.Name); err != nil {
		return model.OrganizationUnit{}, err
	}

	if err := ous.validateOUHandle(request.Handle); err != nil {
		return model.OrganizationUnit{}, err
	}

	existingOU, err := store.GetOrganizationUnit(id)
	if err != nil {
		if errors.Is(err, constants.ErrOrganizationUnitNotFound) {
			return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitNotFound
		}
		logger.Error("Failed to get organization unit", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}

	if request.Parent != nil {
		exists, err := store.IsOrganizationUnitExists(*request.Parent)
		if err != nil {
			logger.Error("Failed to check parent organization unit existence", log.Error(err))
			return model.OrganizationUnit{}, &constants.ErrorInternalServerError
		}
		if !exists {
			return model.OrganizationUnit{}, &constants.ErrorParentOrganizationUnitNotFound
		}
	}

	if err := ous.checkCircularDependency(id, request.Parent); err != nil {
		return model.OrganizationUnit{}, err
	}

	var nameConflict bool
	if existingOU.Parent != request.Parent || existingOU.Name != request.Name {
		nameConflict, err = store.CheckOrganizationUnitNameConflict(request.Name, request.Parent)
		if err != nil {
			logger.Error("Failed to check organization unit name conflict", log.Error(err))
			return model.OrganizationUnit{}, &constants.ErrorInternalServerError
		}
	}

	if nameConflict {
		return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitNameConflict
	}

	var handleConflict bool
	if existingOU.Parent != request.Parent || existingOU.Handle != request.Handle {
		handleConflict, err = store.CheckOrganizationUnitHandleConflict(request.Handle, request.Parent)
		if err != nil {
			logger.Error("Failed to check organization unit handle conflict", log.Error(err))
			return model.OrganizationUnit{}, &constants.ErrorInternalServerError
		}
	}

	if handleConflict {
		return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitHandleConflict
	}

	updatedOU := model.OrganizationUnit{
		ID:          existingOU.ID,
		Handle:      request.Handle,
		Name:        request.Name,
		Description: request.Description,
		Parent:      request.Parent,
	}

	err = store.UpdateOrganizationUnit(updatedOU)
	if err != nil {
		if errors.Is(err, constants.ErrOrganizationUnitNotFound) {
			return model.OrganizationUnit{}, &constants.ErrorOrganizationUnitNotFound
		}
		logger.Error("Failed to update organization unit", log.Error(err))
		return model.OrganizationUnit{}, &constants.ErrorInternalServerError
	}

	logger.Debug("Successfully updated organization unit", log.String("ouID", id))
	return updatedOU, nil
}

// DeleteOrganizationUnit deletes an organization unit.
func (ous *OrganizationUnitService) DeleteOrganizationUnit(id string) *serviceerror.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Deleting organization unit", log.String("ouID", id))

	// Check if organization unit exists
	exists, err := store.IsOrganizationUnitExists(id)
	if err != nil {
		logger.Error("Failed to check organization unit existence", log.Error(err))
		return &constants.ErrorInternalServerError
	}
	if !exists {
		return &constants.ErrorOrganizationUnitNotFound
	}

	hasChildren, err := store.CheckOrganizationUnitHasChildResources(id)
	if err != nil {
		logger.Error("Failed to check if organization unit has children", log.Error(err))
		return &constants.ErrorInternalServerError
	}
	if hasChildren {
		return &constants.ErrorCannotDeleteOrganizationUnit
	}

	err = store.DeleteOrganizationUnit(id)
	if err != nil {
		if errors.Is(err, constants.ErrOrganizationUnitNotFound) {
			return &constants.ErrorOrganizationUnitNotFound
		}
		logger.Error("Failed to delete organization unit", log.Error(err))
		return &constants.ErrorInternalServerError
	}

	logger.Debug("Successfully deleted organization unit", log.String("ouID", id))
	return nil
}

// GetOrganizationUnitUsers retrieves a list of users for a given organization unit ID.
func (ous *OrganizationUnitService) GetOrganizationUnitUsers(
	id string, limit, offset int,
) (*model.UserListResponse, *serviceerror.ServiceError) {
	items, totalCount, svcErr := ous.getResourceListWithExistenceCheck(
		id, limit, offset, "users",
		func(id string, limit, offset int) (interface{}, error) {
			return store.GetOrganizationUnitUsersList(id, limit, offset)
		},
		store.GetOrganizationUnitUsersCount,
	)
	if svcErr != nil {
		return nil, svcErr
	}

	users, ok := items.([]model.User)
	if !ok {
		return nil, &constants.ErrorInternalServerError
	}
	response := &model.UserListResponse{
		TotalResults: totalCount,
		Users:        users,
		StartIndex:   offset + 1,
		Count:        len(users),
		Links:        buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// GetOrganizationUnitGroups retrieves a list of groups for a given organization unit ID.
func (ous *OrganizationUnitService) GetOrganizationUnitGroups(
	id string, limit, offset int,
) (*model.GroupListResponse, *serviceerror.ServiceError) {
	items, totalCount, svcErr := ous.getResourceListWithExistenceCheck(
		id, limit, offset, "groups",
		func(id string, limit, offset int) (interface{}, error) {
			return store.GetOrganizationUnitGroupsList(id, limit, offset)
		},
		store.GetOrganizationUnitGroupsCount,
	)
	if svcErr != nil {
		return nil, svcErr
	}

	groups, ok := items.([]model.Group)
	if !ok {
		return nil, &constants.ErrorInternalServerError
	}
	response := &model.GroupListResponse{
		TotalResults: totalCount,
		Groups:       groups,
		StartIndex:   offset + 1,
		Count:        len(groups),
		Links:        buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// GetOrganizationUnitChildren retrieves a list of child organization units for a given organization unit ID.
func (ous *OrganizationUnitService) GetOrganizationUnitChildren(
	id string, limit, offset int,
) (*model.OrganizationUnitListResponse, *serviceerror.ServiceError) {
	items, totalCount, svcErr := ous.getResourceListWithExistenceCheck(
		id, limit, offset, "child organization units",
		func(id string, limit, offset int) (interface{}, error) {
			return store.GetOrganizationUnitChildrenList(id, limit, offset)
		},
		store.GetOrganizationUnitChildrenCount,
	)
	if svcErr != nil {
		return nil, svcErr
	}

	children, ok := items.([]model.OrganizationUnitBasic)
	if !ok {
		return nil, &constants.ErrorInternalServerError
	}

	response := &model.OrganizationUnitListResponse{
		TotalResults:      totalCount,
		OrganizationUnits: children,
		StartIndex:        offset + 1,
		Count:             len(children),
		Links:             buildPaginationLinks(limit, offset, totalCount),
	}

	return response, nil
}

// checkCircularDependency checks if setting the parent would create a circular dependency.
func (ous *OrganizationUnitService) checkCircularDependency(ouID string, parentID *string) *serviceerror.ServiceError {
	if parentID == nil {
		return nil
	}

	if ouID == *parentID {
		return &constants.ErrorCircularDependency
	}

	currentParentID := parentID
	for currentParentID != nil {
		if *currentParentID == ouID {
			return &constants.ErrorCircularDependency
		}

		parentOU, err := store.GetOrganizationUnit(*currentParentID)
		if err != nil {
			if errors.Is(err, constants.ErrOrganizationUnitNotFound) {
				break
			}
			return &constants.ErrorInternalServerError
		}

		currentParentID = parentOU.Parent
	}

	return nil
}

// validateOUName validates organization unit name.
func (ous *OrganizationUnitService) validateOUName(name string) *serviceerror.ServiceError {
	if strings.TrimSpace(name) == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	return nil
}

// validateOUHandle validates organization unit handle.
func (ous *OrganizationUnitService) validateOUHandle(handle string) *serviceerror.ServiceError {
	if strings.TrimSpace(handle) == "" {
		return &constants.ErrorInvalidRequestFormat
	}

	return nil
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
			Href: fmt.Sprintf("/organization-units?offset=0&limit=%d", limit),
			Rel:  "first",
		})

		prevOffset := offset - limit
		if prevOffset < 0 {
			prevOffset = 0
		}
		links = append(links, model.Link{
			Href: fmt.Sprintf("/organization-units?offset=%d&limit=%d", prevOffset, limit),
			Rel:  "prev",
		})
	}

	if offset+limit < totalCount {
		nextOffset := offset + limit
		links = append(links, model.Link{
			Href: fmt.Sprintf("/organization-units?offset=%d&limit=%d", nextOffset, limit),
			Rel:  "next",
		})
	}

	lastPageOffset := ((totalCount - 1) / limit) * limit
	if offset < lastPageOffset {
		links = append(links, model.Link{
			Href: fmt.Sprintf("/organization-units?offset=%d&limit=%d", lastPageOffset, limit),
			Rel:  "last",
		})
	}

	return links
}

// getResourceListWithExistenceCheck is a generic function to get resources for an
// organization unit with existence check.
func (ous *OrganizationUnitService) getResourceListWithExistenceCheck(
	id string, limit, offset int, resourceType string,
	getListFunc func(string, int, int) (interface{}, error),
	getCountFunc func(string) (int, error),
) (interface{}, int, *serviceerror.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))
	logger.Debug("Getting resource for organization unit", log.String("resource_type", resourceType),
		log.String("ouID", id))

	if err := validatePaginationParams(limit, offset); err != nil {
		return nil, 0, err
	}

	// Check if the organization unit exists
	exists, err := store.IsOrganizationUnitExists(id)
	if err != nil {
		logger.Error("Failed to check organization unit existence", log.Error(err))
		return nil, 0, &constants.ErrorInternalServerError
	}
	if !exists {
		return nil, 0, &constants.ErrorOrganizationUnitNotFound
	}

	items, err := getListFunc(id, limit, offset)
	if err != nil {
		logger.Error("Failed to list resource", log.String("resource_type", resourceType), log.Error(err))
		return nil, 0, &constants.ErrorInternalServerError
	}

	totalCount, err := getCountFunc(id)
	if err != nil {
		logger.Error("Failed to get resource count", log.String("resource_type", resourceType), log.Error(err))
		return nil, 0, &constants.ErrorInternalServerError
	}

	return items, totalCount, nil
}
