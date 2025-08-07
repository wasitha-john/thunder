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

// Package cache provides a cache manager implementation for managing caches.
package cache

import (
	"sync"
	"time"

	"github.com/asgardeo/thunder/internal/system/cache/cache"
	"github.com/asgardeo/thunder/internal/system/cache/constants"
	"github.com/asgardeo/thunder/internal/system/cache/inmemory"
	"github.com/asgardeo/thunder/internal/system/cache/model"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/log"
)

const loggerComponentName = "CacheManager"

// CacheManagerInterface defines the interface for cache manager.
type CacheManagerInterface[T any] interface {
	Set(key model.CacheKey, value T) error
	Get(key model.CacheKey) (T, bool)
	Delete(key model.CacheKey) error
	Clear() error
	IsEnabled() bool
}

// CacheManager implements the CacheManagerInterface for managing caches.
type CacheManager[T any] struct {
	enabled         bool
	Cache           cache.CacheInterface[T]
	cleanUpInterval time.Duration
	mu              sync.RWMutex
}

// NewCacheManager creates a new cache manager instance.
func NewCacheManager[T any](cacheName string) CacheManagerInterface[T] {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	cacheConfig := config.GetThunderRuntime().Config.Cache
	if cacheConfig.Disabled {
		logger.Debug("Caching is disabled, returning empty cache manager")
		return &CacheManager[T]{
			enabled: false,
			Cache:   nil,
		}
	}

	cacheProperty := getCacheProperty(cacheConfig, cacheName)

	if cacheProperty.Disabled {
		logger.Debug("Cache is disabled, returning empty cache manager")
		return &CacheManager[T]{
			enabled: false,
			Cache:   nil,
		}
	}

	logger.Debug("Initializing cache manager")

	cacheType := getCacheType(cacheConfig)
	evictionPolicy := getEvictionPolicy(cacheConfig, cacheProperty)
	cleanupInterval := getCleanupInterval(cacheConfig, cacheProperty)

	size := cacheProperty.Size
	if size <= 0 {
		size = constants.DefaultCacheSize
	}

	ttl := cacheProperty.TTL
	if ttl <= 0 {
		ttl = constants.DefaultCacheTTL
	}

	var cache cache.CacheInterface[T]
	switch cacheType {
	case constants.CacheTypeInMemory:
		cache = inmemory.NewInMemoryCache[T](
			cacheName,
			!cacheProperty.Disabled,
			size,
			time.Duration(ttl)*time.Second,
			evictionPolicy,
		)
	default:
		logger.Warn("Unknown cache type, defaulting to in-memory cache")
		cache = inmemory.NewInMemoryCache[T](
			cacheName,
			!cacheProperty.Disabled,
			constants.DefaultCacheSize,
			constants.DefaultCacheTTL*time.Second,
			constants.EvictionPolicyLRU,
		)
	}

	cm := &CacheManager[T]{
		enabled:         true,
		Cache:           cache,
		cleanUpInterval: cleanupInterval,
	}
	cm.startCleanupRoutine()

	return cm
}

// Set stores a value in the cache.
func (cm *CacheManager[T]) Set(key model.CacheKey, value T) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if cm.IsEnabled() && cm.Cache.IsEnabled() {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		if err := cm.Cache.Set(key, value); err != nil {
			logger.Warn("Failed to set value in the cache", log.String("key", key.ToString()), log.Error(err))
		}
	}

	return nil
}

// Get retrieves a value from the cache.
func (cm *CacheManager[T]) Get(key model.CacheKey) (T, bool) {
	if cm.IsEnabled() && cm.Cache.IsEnabled() {
		cm.mu.RLock()
		defer cm.mu.RUnlock()

		if value, found := cm.Cache.Get(key); found {
			return value, true
		}
	}

	var zero T
	return zero, false
}

// Delete removes a value from the cache.
func (cm *CacheManager[T]) Delete(key model.CacheKey) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if cm.IsEnabled() && cm.Cache.IsEnabled() {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		if err := cm.Cache.Delete(key); err != nil {
			logger.Warn("Failed to delete value from the cache", log.String("key", key.ToString()), log.Error(err))
		}
	}

	return nil
}

// Clear removes all entries in the cache.
func (cm *CacheManager[T]) Clear() error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if cm.IsEnabled() && cm.Cache.IsEnabled() {
		logger.Debug("Clearing all entries in the cache")

		cm.mu.Lock()
		defer cm.mu.Unlock()

		if err := cm.Cache.Clear(); err != nil {
			logger.Warn("Failed to clear the cache", log.Error(err))
		}
	}

	return nil
}

// IsEnabled returns whether the cache manager is enabled.
func (cm *CacheManager[T]) IsEnabled() bool {
	return cm.enabled
}

// startCleanupRoutine starts a background routine to clean up expired entries.
func (cm *CacheManager[T]) startCleanupRoutine() {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	if !cm.IsEnabled() || !cm.Cache.IsEnabled() {
		return
	}

	go func() {
		ticker := time.NewTicker(cm.cleanUpInterval)
		defer ticker.Stop()

		for range ticker.C {
			cm.Cache.CleanupExpired()
		}
	}()

	logger.Debug("Cache cleanup routine started", log.Any("interval", cm.cleanUpInterval))
}

// getCacheType retrieves the cache type from the configuration.
//
//nolint:unparam // TODO: Ignoring linter check as we only support in-memory cache for now.
func getCacheType(cacheConfig config.CacheConfig) constants.CacheType {
	if cacheConfig.Type == "" {
		return constants.CacheTypeInMemory
	}
	switch cacheConfig.Type {
	case string(constants.CacheTypeInMemory):
		return constants.CacheTypeInMemory
	default:
		log.GetLogger().Warn("Unknown cache type, defaulting to in-memory cache")
		return constants.CacheTypeInMemory
	}
}

// getCacheProperty retrieves the cache property for the specified cache name.
func getCacheProperty(cacheConfig config.CacheConfig, cacheName string) config.CacheProperty {
	for _, property := range cacheConfig.Properties {
		if property.Name == cacheName {
			return property
		}
	}
	return config.CacheProperty{}
}

// getEvictionPolicy retrieves the eviction policy from the cache configuration.
func getEvictionPolicy(cacheConfig config.CacheConfig, cacheProperty config.CacheProperty) constants.EvictionPolicy {
	evictionPolicy := cacheProperty.EvictionPolicy
	if evictionPolicy == "" {
		evictionPolicy = cacheConfig.EvictionPolicy
	}
	if evictionPolicy == "" {
		return constants.EvictionPolicyLRU
	}

	switch evictionPolicy {
	case string(constants.EvictionPolicyLRU):
		return constants.EvictionPolicyLRU
	case string(constants.EvictionPolicyLFU):
		return constants.EvictionPolicyLFU
	default:
		log.GetLogger().Warn("Unknown eviction policy, defaulting to LRU")
		return constants.EvictionPolicyLRU
	}
}

// getCleanupInterval retrieves the cleanup interval from the cache configuration.
func getCleanupInterval(cacheConfig config.CacheConfig, cacheProperty config.CacheProperty) time.Duration {
	cleanupIntervalInt := cacheProperty.CleanupInterval
	if cleanupIntervalInt <= 0 {
		cleanupIntervalInt = cacheConfig.CleanupInterval
	}
	if cleanupIntervalInt <= 0 {
		cleanupIntervalInt = constants.DefaultCleanupInterval
	}

	return time.Duration(cleanupIntervalInt) * time.Second
}
