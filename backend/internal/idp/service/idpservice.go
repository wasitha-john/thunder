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

// Package service provides the implementation for IdP management operations.
package service

import (
	"errors"

	"github.com/asgardeo/thunder/internal/idp/model"
	"github.com/asgardeo/thunder/internal/idp/store"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// IDPServiceInterface defines the interface for the IdP service.
type IDPServiceInterface interface {
	CreateIdentityProvider(idp *model.IDP) (*model.IDP, error)
	GetIdentityProviderList() ([]model.IDP, error)
	GetIdentityProvider(idpID string) (*model.IDP, error)
	GetIdentityProviderByName(idpName string) (*model.IDP, error)
	UpdateIdentityProvider(idpID string, idp *model.IDP) (*model.IDP, error)
	DeleteIdentityProvider(idpID string) error
}

// IDPService is the default implementation of the IdPServiceInterface.
type IDPService struct{}

// GetIDPService creates a new instance of IdPService.
func GetIDPService() IDPServiceInterface {
	return &IDPService{}
}

// CreateIdentityProvider creates the IdP.
func (is *IDPService) CreateIdentityProvider(idp *model.IDP) (*model.IDP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPService"))

	idp.ID = utils.GenerateUUID()

	// Create the IdP in the database.
	err := store.CreateIdentityProvider(*idp)
	if err != nil {
		logger.Error("Failed to create IdP", log.Error(err))
		return nil, err
	}
	return idp, nil
}

// GetIdentityProviderList list the IdPs.
func (is *IDPService) GetIdentityProviderList() ([]model.IDP, error) {
	idps, err := store.GetIdentityProviderList()
	if err != nil {
		return nil, err
	}

	return idps, nil
}

// GetIdentityProvider get the IdP for given IdP id.
func (is *IDPService) GetIdentityProvider(idpID string) (*model.IDP, error) {
	if idpID == "" {
		return nil, errors.New("IdP ID is empty")
	}

	idp, err := store.GetIdentityProvider(idpID)
	if err != nil {
		return nil, err
	}

	return &idp, nil
}

// GetIdentityProviderByName get the IdP for given IdP name.
func (is *IDPService) GetIdentityProviderByName(idpName string) (*model.IDP, error) {
	if idpName == "" {
		return nil, errors.New("IdP name is empty")
	}

	idp, err := store.GetIdentityProviderByName(idpName)
	if err != nil {
		return nil, err
	}

	return &idp, nil
}

// UpdateIdentityProvider update the IdP for given IdP id.
func (is *IDPService) UpdateIdentityProvider(idpID string, idp *model.IDP) (*model.IDP, error) {
	if idpID == "" {
		return nil, errors.New("IdP ID is empty")
	}

	err := store.UpdateIdentityProvider(idp)
	if err != nil {
		return nil, err
	}

	return idp, nil
}

// DeleteIdentityProvider delete the IdP for given IdP id.
func (is *IDPService) DeleteIdentityProvider(idpID string) error {
	if idpID == "" {
		return errors.New("IdP ID is empty")
	}

	err := store.DeleteIdentityProvider(idpID)
	if err != nil {
		return err
	}

	return nil
}
