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

package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/cache/constants"
	"github.com/asgardeo/thunder/internal/system/cache/model"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/tests/mocks/cachemock"
)

const (
	testValue = "testValue"
)

type CacheManagerTestSuite struct {
	suite.Suite
}

func TestCacheManagerSuite(t *testing.T) {
	suite.Run(t, new(CacheManagerTestSuite))
}

func (suite *CacheManagerTestSuite) TestIsEnabled() {
	t := suite.T()

	// Test enabled cache manager
	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	enabledManager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}
	assert.True(t, enabledManager.IsEnabled())

	// Test disabled cache manager
	disabledManager := &CacheManager[string]{
		enabled: false,
		Cache:   nil,
	}
	assert.False(t, disabledManager.IsEnabled())
}

func (suite *CacheManagerTestSuite) TestSet() {
	t := suite.T()

	// Test with enabled cache manager and cache
	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	key := model.CacheKey{Key: "testKey"}

	// Set up expectation for Set
	mockCache.EXPECT().Set(key, testValue).Return(nil)

	// Call Set and verify
	err := manager.Set(key, testValue)
	assert.NoError(t, err)

	// Test with disabled cache manager
	disabledManager := &CacheManager[string]{
		enabled: false,
		Cache:   nil,
	}

	// Should be a no-op with disabled manager
	err = disabledManager.Set(key, testValue)
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestSetWithError() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	key := model.CacheKey{Key: "testKey"}

	// Set up expectation for Set to return error
	mockCache.EXPECT().Set(key, testValue).Return(fmt.Errorf("set error"))

	// Even with error, Set should not return error (logged instead)
	err := manager.Set(key, testValue)
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestGet() {
	t := suite.T()

	// Test 1: Test with enabled cache manager and value found
	mockCache1 := cachemock.NewCacheInterfaceMock[string](t)
	mockCache1.EXPECT().IsEnabled().Return(true)

	manager1 := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache1,
		cleanUpInterval: 60 * time.Second,
	}

	key := model.CacheKey{Key: "testKey"}

	mockCache1.EXPECT().Get(key).Return(testValue, true)
	value, found := manager1.Get(key)
	assert.True(t, found)
	assert.Equal(t, testValue, value)

	// Test 2: Test with enabled cache manager and value not found
	mockCache2 := cachemock.NewCacheInterfaceMock[string](t)
	mockCache2.EXPECT().IsEnabled().Return(true)

	manager2 := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache2,
		cleanUpInterval: 60 * time.Second,
	}

	mockCache2.EXPECT().Get(key).Return("", false)
	value2, found2 := manager2.Get(key)
	assert.False(t, found2)
	assert.Equal(t, "", value2)

	// Test 3: Test with disabled cache manager
	disabledManager := &CacheManager[string]{
		enabled: false,
		Cache:   nil,
	}

	// Should return not found with disabled manager
	value3, found3 := disabledManager.Get(key)
	assert.False(t, found3)
	assert.Equal(t, "", value3)
}

func (suite *CacheManagerTestSuite) TestDelete() {
	t := suite.T()

	// Test with enabled cache manager and cache
	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	key := model.CacheKey{Key: "testKey"}

	// Set up expectation for Delete
	mockCache.EXPECT().Delete(key).Return(nil)

	// Call Delete and verify
	err := manager.Delete(key)
	assert.NoError(t, err)

	// Test with disabled cache manager
	disabledManager := &CacheManager[string]{
		enabled: false,
		Cache:   nil,
	}

	// Should be a no-op with disabled manager
	err = disabledManager.Delete(key)
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestDeleteWithError() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	key := model.CacheKey{Key: "testKey"}

	// Set up expectation for Delete to return error
	mockCache.EXPECT().Delete(key).Return(fmt.Errorf("delete error"))

	// Even with error, Delete should not return error (logged instead)
	err := manager.Delete(key)
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestClear() {
	t := suite.T()

	// Test with enabled cache manager and cache
	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Set up expectation for Clear
	mockCache.EXPECT().Clear().Return(nil)

	// Call Clear and verify
	err := manager.Clear()
	assert.NoError(t, err)

	// Test with disabled cache manager
	disabledManager := &CacheManager[string]{
		enabled: false,
		Cache:   nil,
	}

	// Should be a no-op with disabled manager
	err = disabledManager.Clear()
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestClearWithError() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Set up expectation for Clear to return error
	mockCache.EXPECT().Clear().Return(fmt.Errorf("clear error"))

	// Even with error, Clear should not return error (logged instead)
	err := manager.Clear()
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestGetCacheProperty() {
	testCases := []struct {
		name             string
		cacheName        string
		cacheConfig      config.CacheConfig
		expectedProperty config.CacheProperty
	}{
		{
			name:      "ExistingProperty",
			cacheName: "testCache",
			cacheConfig: config.CacheConfig{
				Properties: []config.CacheProperty{
					{
						Name:     "testCache",
						Disabled: false,
						Size:     100,
						TTL:      60,
					},
				},
			},
			expectedProperty: config.CacheProperty{
				Name:     "testCache",
				Disabled: false,
				Size:     100,
				TTL:      60,
			},
		},
		{
			name:      "NonExistingProperty",
			cacheName: "nonExistingCache",
			cacheConfig: config.CacheConfig{
				Properties: []config.CacheProperty{
					{
						Name:     "testCache",
						Disabled: false,
						Size:     100,
						TTL:      60,
					},
				},
			},
			expectedProperty: config.CacheProperty{},
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			property := getCacheProperty(tc.cacheConfig, tc.cacheName)
			assert.Equal(t, tc.expectedProperty, property)
		})
	}
}

func (suite *CacheManagerTestSuite) TestGetEvictionPolicy() {
	testCases := []struct {
		name                   string
		cacheConfig            config.CacheConfig
		cacheProperty          config.CacheProperty
		expectedEvictionPolicy constants.EvictionPolicy
	}{
		{
			name: "PropertyLFUEvictionPolicy",
			cacheConfig: config.CacheConfig{
				EvictionPolicy: string(constants.EvictionPolicyLRU),
			},
			cacheProperty: config.CacheProperty{
				EvictionPolicy: string(constants.EvictionPolicyLFU),
			},
			expectedEvictionPolicy: constants.EvictionPolicyLFU,
		},
		{
			name: "ConfigLRUEvictionPolicy",
			cacheConfig: config.CacheConfig{
				EvictionPolicy: string(constants.EvictionPolicyLRU),
			},
			cacheProperty:          config.CacheProperty{},
			expectedEvictionPolicy: constants.EvictionPolicyLRU,
		},
		{
			name:                   "DefaultLRUEvictionPolicy",
			cacheConfig:            config.CacheConfig{},
			cacheProperty:          config.CacheProperty{},
			expectedEvictionPolicy: constants.EvictionPolicyLRU,
		},
		{
			name: "InvalidEvictionPolicy",
			cacheConfig: config.CacheConfig{
				EvictionPolicy: "INVALID",
			},
			cacheProperty:          config.CacheProperty{},
			expectedEvictionPolicy: constants.EvictionPolicyLRU,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			evictionPolicy := getEvictionPolicy(tc.cacheConfig, tc.cacheProperty)
			assert.Equal(t, tc.expectedEvictionPolicy, evictionPolicy)
		})
	}
}

func (suite *CacheManagerTestSuite) TestGetCacheType() {
	testCases := []struct {
		name              string
		cacheConfig       config.CacheConfig
		expectedCacheType constants.CacheType
	}{
		{
			name: "InMemoryCacheType",
			cacheConfig: config.CacheConfig{
				Type: string(constants.CacheTypeInMemory),
			},
			expectedCacheType: constants.CacheTypeInMemory,
		},
		{
			name:              "DefaultCacheType",
			cacheConfig:       config.CacheConfig{},
			expectedCacheType: constants.CacheTypeInMemory,
		},
		{
			name: "UnknownCacheType",
			cacheConfig: config.CacheConfig{
				Type: "unknown",
			},
			expectedCacheType: constants.CacheTypeInMemory,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			cacheType := getCacheType(tc.cacheConfig)
			assert.Equal(t, tc.expectedCacheType, cacheType)
		})
	}
}

func (suite *CacheManagerTestSuite) TestGetCleanupInterval() {
	testCases := []struct {
		name                    string
		cacheConfig             config.CacheConfig
		cacheProperty           config.CacheProperty
		expectedCleanupInterval time.Duration
	}{
		{
			name: "PropertyCleanupInterval",
			cacheConfig: config.CacheConfig{
				CleanupInterval: 60,
			},
			cacheProperty: config.CacheProperty{
				CleanupInterval: 120,
			},
			expectedCleanupInterval: 120 * time.Second,
		},
		{
			name: "ConfigCleanupInterval",
			cacheConfig: config.CacheConfig{
				CleanupInterval: 60,
			},
			cacheProperty:           config.CacheProperty{},
			expectedCleanupInterval: 60 * time.Second,
		},
		{
			name:                    "DefaultCleanupInterval",
			cacheConfig:             config.CacheConfig{},
			cacheProperty:           config.CacheProperty{},
			expectedCleanupInterval: constants.DefaultCleanupInterval * time.Second,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			cleanupInterval := getCleanupInterval(tc.cacheConfig, tc.cacheProperty)
			assert.Equal(t, tc.expectedCleanupInterval, cleanupInterval)
		})
	}
}

func (suite *CacheManagerTestSuite) TestCacheManagerWithFailingOperations() {
	t := suite.T()

	// Create a mock cache for testing error scenarios
	mockCache := cachemock.NewCacheInterfaceMock[string](t)

	// Configure the mock
	mockCache.EXPECT().IsEnabled().Return(true).Maybe()
	mockCache.EXPECT().GetName().Return("mockErrorCache").Maybe()

	// Create a cache manager with the mock
	cacheManager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Test Set with error
	key := model.CacheKey{Key: "testKey"}

	// Configure mock to return error on Set
	mockCache.EXPECT().Set(key, testValue).Return(fmt.Errorf("set error"))

	// Set should not return the error but log it
	err := cacheManager.Set(key, testValue)
	assert.NoError(t, err)

	// Test Delete with error
	// Configure mock to return error on Delete
	mockCache.EXPECT().Delete(key).Return(fmt.Errorf("delete error"))

	// Delete should not return the error but log it
	err = cacheManager.Delete(key)
	assert.NoError(t, err)

	// Test Clear with error
	// Configure mock to return error on Clear
	mockCache.EXPECT().Clear().Return(fmt.Errorf("clear error"))

	// Clear should not return the error but log it
	err = cacheManager.Clear()
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestDisabledInnerCacheScenario() {
	t := suite.T()

	// Create a mock cache for testing
	mockCache := cachemock.NewCacheInterfaceMock[string](t)

	// Configure the mock to indicate it's disabled
	mockCache.EXPECT().IsEnabled().Return(false)
	// Since it's disabled, no other methods should be called

	// Create a cache manager with the mock
	cacheManager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Test operations with disabled inner cache
	key := model.CacheKey{Key: "testKey"}

	// Set should be a no-op with disabled inner cache
	err := cacheManager.Set(key, testValue)
	assert.NoError(t, err)

	// Get should return not found with disabled inner cache
	retrievedValue, found := cacheManager.Get(key)
	assert.False(t, found)
	var zero string
	assert.Equal(t, zero, retrievedValue)

	// Delete should be a no-op with disabled inner cache
	err = cacheManager.Delete(key)
	assert.NoError(t, err)

	// Clear should be a no-op with disabled inner cache
	err = cacheManager.Clear()
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestDisabledInnerCacheOnly() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(false)
	// Since it's disabled, check IsEnabled multiple times for each operation
	mockCache.EXPECT().IsEnabled().Return(false)
	mockCache.EXPECT().IsEnabled().Return(false)
	mockCache.EXPECT().IsEnabled().Return(false)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Test operations with disabled inner cache
	key := model.CacheKey{Key: "testKey"}

	// All operations should be no-ops when inner cache is disabled
	err := manager.Set(key, testValue)
	assert.NoError(t, err)

	val, found := manager.Get(key)
	assert.False(t, found)
	assert.Equal(t, "", val)

	err = manager.Delete(key)
	assert.NoError(t, err)

	err = manager.Clear()
	assert.NoError(t, err)
}

func (suite *CacheManagerTestSuite) TestGetStats() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)

	expectedStats := model.CacheStat{
		Enabled:    true,
		Size:       10,
		MaxSize:    100,
		HitCount:   5,
		MissCount:  3,
		HitRate:    0.625,
		EvictCount: 1,
	}
	mockCache.EXPECT().GetStats().Return(expectedStats)

	manager := &CacheManager[string]{
		Cache: mockCache,
	}

	stats := manager.Cache.GetStats()
	assert.Equal(t, expectedStats, stats)

	// Test with disabled manager
	disabledManager := &CacheManager[string]{
		Cache: nil,
	}

	// Should not panic with nil cache
	var emptyStats model.CacheStat
	if disabledManager.Cache != nil {
		emptyStats = disabledManager.Cache.GetStats()
	}
	assert.Equal(t, model.CacheStat{}, emptyStats)
}

func (suite *CacheManagerTestSuite) TestMultipleValues() {
	t := suite.T()

	mockCache := cachemock.NewCacheInterfaceMock[string](t)
	// Need to set multiple expectations for multiple IsEnabled calls
	mockCache.EXPECT().IsEnabled().Return(true)
	mockCache.EXPECT().IsEnabled().Return(true)
	mockCache.EXPECT().IsEnabled().Return(true)

	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: 60 * time.Second,
	}

	// Define test data
	keys := []model.CacheKey{
		{Key: "key1"},
		{Key: "key2"},
		{Key: "key3"},
	}
	values := []string{"value1", "value2", "value3"}

	// Test Set operations
	for i := range keys {
		mockCache.EXPECT().Set(keys[i], values[i]).Return(nil)
		err := manager.Set(keys[i], values[i])
		assert.NoError(t, err)
	}

	// Test Get operations with different outcomes
	mockCache.EXPECT().Get(keys[0]).Return(values[0], true)
	mockCache.EXPECT().Get(keys[1]).Return("", false)
	mockCache.EXPECT().Get(keys[2]).Return(values[2], true)

	val1, found1 := manager.Get(keys[0])
	assert.True(t, found1)
	assert.Equal(t, values[0], val1)

	val2, found2 := manager.Get(keys[1])
	assert.False(t, found2)
	assert.Equal(t, "", val2)

	val3, found3 := manager.Get(keys[2])
	assert.True(t, found3)
	assert.Equal(t, values[2], val3)
}
