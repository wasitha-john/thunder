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
	"reflect"
	"sync"

	"github.com/asgardeo/thunder/internal/system/log"
)

// cacheStore is a singleton that holds all cache managers.
type cacheStore struct {
	caches map[string]interface{}
	mu     sync.RWMutex
}

var (
	instance *cacheStore
	once     sync.Once
)

// getCacheStore returns the singleton instance of the cache store.
func getCacheStore() *cacheStore {
	once.Do(func() {
		instance = &cacheStore{
			caches: make(map[string]interface{}),
		}
	})
	return instance
}

// GetCacheManager returns a singleton cache manager for the given type and cache name.
func GetCacheManager[T any](cacheName string) CacheManagerInterface[T] {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "CacheManager"))

	cp := getCacheStore()

	// Create unique key for the cache manager
	var t T
	typeName := reflect.TypeOf(t).String()
	cacheKey := cacheName + ":" + typeName

	// First try to get from the map
	cp.mu.RLock()
	if cm, exists := cp.caches[cacheKey]; exists {
		cp.mu.RUnlock()
		if retCM, ok := cm.(CacheManagerInterface[T]); ok {
			return retCM
		}
		logger.Warn("Type mismatch for cache manager", log.String("cacheName", cacheName),
			log.String("expectedType", typeName), log.String("actualType", reflect.TypeOf(cm).String()))

		return nil
	}
	cp.mu.RUnlock()

	// Acquire write lock to create a new cache manager
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cm, exists := cp.caches[cacheKey]; exists {
		if retCM, ok := cm.(CacheManagerInterface[T]); ok {
			return retCM
		}
		logger.Warn("Type mismatch for cache manager", log.String("cacheName", cacheName),
			log.String("expectedType", typeName), log.String("actualType", reflect.TypeOf(cm).String()))

		return nil
	}

	// Create a new cache manager
	logger.Debug("Creating new cache manager", log.String("cacheName", cacheName), log.String("type", typeName))
	newCM := newCacheManager[T](cacheName)
	cp.caches[cacheKey] = newCM

	return newCM
}

// resetCacheStore is used for testing purposes to reset the cache store state.
func resetCacheStore() {
	if instance != nil {
		instance.mu.Lock()
		instance.caches = make(map[string]interface{})
		instance.mu.Unlock()
	}
}
