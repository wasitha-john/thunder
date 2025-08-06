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

// Package constants provides common constants used across caching.
package constants

// EvictionPolicy defines the eviction policy for cache entries.
type EvictionPolicy string

const (
	// EvictionPolicyLRU represents the Least Recently Used eviction policy.
	EvictionPolicyLRU EvictionPolicy = "LRU"
	// EvictionPolicyLFU represents the Least Frequently Used eviction policy.
	EvictionPolicyLFU EvictionPolicy = "LFU"
)

// CacheType defines the type of cache being used.
type CacheType string

const (
	// CacheTypeInMemory represents an in-memory cache type.
	CacheTypeInMemory CacheType = "inmemory"
)

const (
	// DefaultCleanupInterval represents the default interval for cleaning up caches.
	DefaultCleanupInterval = 300
	// DefaultCacheTTL represents the default TTL for cache entries in seconds.
	DefaultCacheTTL = 3600
	// DefaultCacheSize represents the default size for the caches.
	DefaultCacheSize = 1000
)
