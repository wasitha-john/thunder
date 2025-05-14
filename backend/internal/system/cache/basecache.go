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
	"time"
)

// CacheKey represents a key for the cache.
type CacheKey struct {
	Key string
}

// ToString returns the string representation of the CacheKey.
func (key CacheKey) ToString() string {

	return key.Key
}

// CacheEntry represents a cache entry.
type CacheEntry struct {
	Value      interface{}
	ExpiryTime time.Time
}

// BaseCacheInterface defines the interface for cache.
type BaseCacheInterface interface {
	AddToCache(key CacheKey, entry *CacheEntry)
	GetValueFromCache(key CacheKey) *CacheEntry
	ClearCacheEntry(key CacheKey)
	ClearCache()
}

// BaseCache provides core caching functionality.
type BaseCache struct {
	cache map[CacheKey]*CacheEntry
	mu    sync.RWMutex
}

// NewBaseCache creates a new instance of BaseCache.
func NewBaseCache() *BaseCache {
	return &BaseCache{
		cache: make(map[CacheKey]*CacheEntry),
	}
}

// AddToCache adds an entry to the cache with a validity period.
func (bc *BaseCache) AddToCache(key CacheKey, entry *CacheEntry) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.cache[CacheKey(key)] = entry
}

// GetValueFromCache retrieves a value from the cache if it is still valid.
func (bc *BaseCache) GetValueFromCache(key CacheKey) *CacheEntry {
	bc.mu.RLock()
	entry, exists := bc.cache[CacheKey(key)]
	bc.mu.RUnlock()

	if !exists || time.Now().After(entry.ExpiryTime) {
		// Remove the expired entry.
		bc.mu.Lock()
		delete(bc.cache, CacheKey(key))
		bc.mu.Unlock()

		return nil
	}

	return entry
}

// ClearCacheEntry removes a specific entry from the cache.
func (bc *BaseCache) ClearCacheEntry(key CacheKey) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	delete(bc.cache, CacheKey(key))
}

// ClearCache removes all entries from the cache.
func (bc *BaseCache) ClearCache() {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.cache = make(map[CacheKey]*CacheEntry)
}
