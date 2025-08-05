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

package seeder

import (
	"github.com/asgardeo/thunder/internal/system/database/provider"
)

var seederProvider SeederProviderInterface

// SeederProviderInterface defines the interface for providing seeder instances.
type SeederProviderInterface interface {
	GetSeeder(dbName string) (SeederInterface, error)
}

// SeederProvider implements SeederProviderInterface.
type SeederProvider struct {
	dbProvider provider.DBProviderInterface
}

// NewSeederProvider creates a new instance of SeederProvider.
func NewSeederProvider(dbProvider provider.DBProviderInterface) SeederProviderInterface {
	return &SeederProvider{
		dbProvider: dbProvider,
	}
}

// GetSeeder returns a seeder instance for the specified database.
func (p *SeederProvider) GetSeeder(dbName string) (SeederInterface, error) {
	dbClient, err := p.dbProvider.GetDBClient(dbName)
	if err != nil {
		return nil, err
	}
	
	return NewDBSeeder(dbClient), nil
}

// SetSeederProvider sets the global seeder provider instance.
func SetSeederProvider(provider SeederProviderInterface) {
	seederProvider = provider
}

// GetSeederProvider returns the global seeder provider instance.
func GetSeederProvider() SeederProviderInterface {
	if seederProvider == nil {
		panic("SeederProvider is not initialized")
	}
	return seederProvider
}