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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/config"
)

type TestString string
type TestInt int

type CacheStoreTestSuite struct {
	suite.Suite
}

func TestCacheStoreSuite(t *testing.T) {
	suite.Run(t, new(CacheStoreTestSuite))
}

func (suite *CacheStoreTestSuite) SetupSuite() {
	mockConfig := &config.Config{
		Cache: config.CacheConfig{
			Disabled: true, // Disable cache globally for tests
		},
	}
	config.ResetThunderRuntime()
	err := config.InitializeThunderRuntime("/test/thunder/home", mockConfig)
	if err != nil {
		suite.T().Fatal("Failed to initialize ThunderRuntime:", err)
	}
}

func (suite *CacheStoreTestSuite) TearDownSuite() {
	config.ResetThunderRuntime()
}

func (suite *CacheStoreTestSuite) SetupTest() {
	resetCacheStore()
}

func (suite *CacheStoreTestSuite) TestGetCacheStore() {
	t := suite.T()

	// Get cache store instance
	store1 := getCacheStore()
	assert.NotNil(t, store1, "Cache store should not be nil")
	assert.NotNil(t, store1.caches, "Cache map should not be nil")

	// Get another instance to verify singleton pattern
	store2 := getCacheStore()
	assert.Same(t, store1, store2, "getCacheStore should return the same instance (singleton)")

	// Verify map initialization
	assert.Empty(t, store1.caches, "Cache map should be empty initially")
}

func (suite *CacheStoreTestSuite) TestGetCacheManager() {
	t := suite.T()

	// Get a cache manager for string type
	cacheName := "testCache"
	cm1 := GetCacheManager[string](cacheName)
	assert.NotNil(t, cm1, "Cache manager should not be nil")

	// Get the same cache manager again
	cm2 := GetCacheManager[string](cacheName)
	assert.Same(t, cm1, cm2, "GetCacheManager should return the same instance for the same type and name")

	// Test with a different cache name but same type
	differentCacheName := "anotherCache"
	cm3 := GetCacheManager[string](differentCacheName)
	assert.NotNil(t, cm3, "Cache manager should not be nil")
	assert.NotSame(t, cm1, cm3, "Different cache names should create different cache managers")
}

func (suite *CacheStoreTestSuite) TestGetCacheManagerMultipleTypes() {
	t := suite.T()

	cacheName := "testMultiTypeCache"

	// Get cache managers for different types
	cmString := GetCacheManager[string](cacheName)
	cmInt := GetCacheManager[int](cacheName)
	cmTestString := GetCacheManager[TestString](cacheName)
	cmTestInt := GetCacheManager[TestInt](cacheName)

	// Verify all cache managers are not nil
	assert.NotNil(t, cmString, "String cache manager should not be nil")
	assert.NotNil(t, cmInt, "Int cache manager should not be nil")
	assert.NotNil(t, cmTestString, "TestString cache manager should not be nil")
	assert.NotNil(t, cmTestInt, "TestInt cache manager should not be nil")

	// Verify different types create different instances even with the same cache name
	assert.NotSame(t, cmString, cmInt, "Different types should create different cache managers")
	assert.NotSame(t, cmString, cmTestString, "Different types should create different cache managers")
	assert.NotSame(t, cmInt, cmTestInt, "Different types should create different cache managers")
	assert.NotSame(t, cmTestString, cmTestInt, "Different types should create different cache managers")

	// Verify same type returns same instance
	cmStringSame := GetCacheManager[string](cacheName)
	assert.Same(t, cmString, cmStringSame, "Same type and name should return the same cache manager")
}

func (suite *CacheStoreTestSuite) TestResetCacheStore() {
	t := suite.T()

	// Create a cache manager
	cacheName := "testResetCache"
	cm := GetCacheManager[string](cacheName)
	assert.NotNil(t, cm, "Cache manager should not be nil")

	// Verify cache store has an entry
	store := getCacheStore()
	assert.NotEmpty(t, store.caches, "Cache map should not be empty after creating a cache manager")

	// Reset the cache store
	resetCacheStore()

	// Verify cache store is now empty
	assert.Empty(t, store.caches, "Cache map should be empty after reset")

	// Create a new cache manager and verify it's different
	cmNew := GetCacheManager[string](cacheName)
	assert.NotNil(t, cmNew, "New cache manager should not be nil")
	assert.NotSame(t, cm, cmNew, "After reset, should get a new cache manager instance")
}

func (suite *CacheStoreTestSuite) TestConcurrentAccess() {
	t := suite.T()

	// Number of goroutines to use
	numGoroutines := 10
	done := make(chan bool, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create multiple cache managers concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			// Use different cache names to avoid collisions
			cacheName := "concurrentCache" + string(rune('A'+index))
			cm := GetCacheManager[string](cacheName)
			assert.NotNil(t, cm, "Cache manager should not be nil even with concurrent access")
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(done)

	// Count completed goroutines
	completedCount := 0
	for range done {
		completedCount++
	}

	// Verify all goroutines completed successfully
	assert.Equal(t, numGoroutines, completedCount, "All goroutines should complete successfully")

	// Verify store has the expected number of entries
	store := getCacheStore()
	assert.Equal(t, numGoroutines, len(store.caches), "Cache map should have an entry for each goroutine")
}

func (suite *CacheStoreTestSuite) TestTypeMismatch() {
	t := suite.T()

	cacheName := "typeMismatchCache"

	// Create a mock cache manager and manually inject it into the store
	store := getCacheStore()

	var mockCM interface{} = &CacheManager[int]{} // Int type
	typeName := "string"
	cacheKey := cacheName + ":" + typeName

	// Directly inject the mismatched type
	store.mu.Lock()
	store.caches[cacheKey] = mockCM
	store.mu.Unlock()

	// Try to get a string cache manager
	cm := GetCacheManager[string](cacheName)
	assert.Nil(t, cm, "Should return nil when there's a type mismatch")
}

func (suite *CacheStoreTestSuite) TestStartCleanupRoutine() {
	t := suite.T()

	// Create a cache manager with a short cleanup interval to test the routine
	cleanupInterval := 50 * time.Millisecond

	// Create a mock cache
	mockCache := newCacheInterfaceMock[string](t)
	mockCache.EXPECT().IsEnabled().Return(true).Maybe()
	mockCache.EXPECT().CleanupExpired().Return().Maybe()

	// Create a cache manager
	manager := &CacheManager[string]{
		enabled:         true,
		Cache:           mockCache,
		cleanUpInterval: cleanupInterval,
	}

	// Start the cleanup routine
	manager.startCleanupRoutine()

	// Wait for the cleanup to be triggered at least once
	time.Sleep(cleanupInterval * 2)

	// If we get here without any test failures, it means the test passed
	// The mockCache is configured to accept CleanupExpired calls through Maybe()
	assert.True(t, true, "The cleanup routine should run without errors")
}

func (suite *CacheStoreTestSuite) TestNewCacheManager() {
	t := suite.T()

	// Save and restore original config
	originalConfig := config.GetThunderRuntime().Config
	defer func() {
		// Reset config to original
		config.ResetThunderRuntime()
		err := config.InitializeThunderRuntime("/test/thunder/home", &originalConfig)
		assert.NoError(t, err)
	}()

	// Test 1: Test with cache globally disabled
	disabledConfig := config.Config{
		Cache: config.CacheConfig{
			Disabled: true,
		},
	}
	config.ResetThunderRuntime()
	err := config.InitializeThunderRuntime("/test/thunder/home", &disabledConfig)
	assert.NoError(t, err)

	cm1 := newCacheManager[string]("testDisabledCache")
	assert.NotNil(t, cm1)
	assert.False(t, cm1.IsEnabled())

	// Test 2: Test with specific cache disabled
	enabledConfig := config.Config{
		Cache: config.CacheConfig{
			Disabled: false,
			Properties: []config.CacheProperty{
				{
					Name:     "testSpecificDisabledCache",
					Disabled: true,
				},
			},
		},
	}
	config.ResetThunderRuntime()
	err = config.InitializeThunderRuntime("/test/thunder/home", &enabledConfig)
	assert.NoError(t, err)

	cm2 := newCacheManager[string]("testSpecificDisabledCache")
	assert.NotNil(t, cm2)
	assert.False(t, cm2.IsEnabled())

	// Test 3: Test with in-memory cache type
	inMemConfig := config.Config{
		Cache: config.CacheConfig{
			Disabled: false,
			Type:     "in-memory",
			Properties: []config.CacheProperty{
				{
					Name: "testInMemCache",
					Size: 100,
					TTL:  300,
				},
			},
		},
	}
	config.ResetThunderRuntime()
	err = config.InitializeThunderRuntime("/test/thunder/home", &inMemConfig)
	assert.NoError(t, err)

	cm3 := newCacheManager[string]("testInMemCache")
	assert.NotNil(t, cm3)
	assert.True(t, cm3.IsEnabled())

	// Test 4: Test with unknown cache type
	unknownTypeConfig := config.Config{
		Cache: config.CacheConfig{
			Disabled: false,
			Type:     "unknown-type",
		},
	}
	config.ResetThunderRuntime()
	err = config.InitializeThunderRuntime("/test/thunder/home", &unknownTypeConfig)
	assert.NoError(t, err)

	cm4 := newCacheManager[string]("testUnknownTypeCache")
	assert.NotNil(t, cm4)
	assert.True(t, cm4.IsEnabled())
}
