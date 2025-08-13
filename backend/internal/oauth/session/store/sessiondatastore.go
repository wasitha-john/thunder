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

// Package store provides functionality for managing auth session data storage.
package store

import (
	"sync"
	"time"

	"github.com/asgardeo/thunder/internal/oauth/session/model"
)

// SessionDataStoreInterface defines the interface for session data storage.
type SessionDataStoreInterface interface {
	AddSession(key string, value model.SessionData)
	GetSession(key string) (bool, model.SessionData)
	ClearSession(key string)
	ClearSessionStore()
}

// sessionStoreEntry represents an entry in the session data store.
type sessionStoreEntry struct {
	sessionData model.SessionData
	expiryTime  time.Time
}

// SessionDataStore provides the session data store functionality.
type SessionDataStore struct {
	sessionStore   map[string]sessionStoreEntry
	validityPeriod time.Duration
	mu             sync.RWMutex
}

var (
	instance *SessionDataStore
	once     sync.Once
)

// GetSessionDataStore returns a singleton instance of SessionDataStore.
func GetSessionDataStore() SessionDataStoreInterface {
	once.Do(func() {
		instance = &SessionDataStore{
			sessionStore:   make(map[string]sessionStoreEntry),
			validityPeriod: 10 * time.Minute, // Set a default validity period.
		}
	})

	return instance
}

// AddSession adds a session data entry to the session store.
func (sds *SessionDataStore) AddSession(key string, value model.SessionData) {
	if key == "" {
		return
	}

	sds.mu.Lock()
	defer sds.mu.Unlock()

	sds.sessionStore[key] = sessionStoreEntry{
		sessionData: value,
		expiryTime:  time.Now().Add(sds.validityPeriod),
	}
}

// GetSession retrieves a session data entry from the session store.
func (sdc *SessionDataStore) GetSession(key string) (bool, model.SessionData) {
	if key == "" {
		return false, model.SessionData{}
	}

	sdc.mu.RLock()
	entry, exists := sdc.sessionStore[key]
	sdc.mu.RUnlock()

	if exists {
		if time.Now().Before(entry.expiryTime) {
			return true, entry.sessionData
		} else {
			// Remove the expired entry.
			sdc.mu.Lock()
			delete(sdc.sessionStore, key)
			sdc.mu.Unlock()
		}
	}

	return false, model.SessionData{}
}

// ClearSession removes a specific session data entry from the session store.
func (sdc *SessionDataStore) ClearSession(key string) {
	if key == "" {
		return
	}

	sdc.mu.Lock()
	defer sdc.mu.Unlock()
	delete(sdc.sessionStore, key)
}

// ClearSessionStore removes all session data entries from the session store.
func (sdc *SessionDataStore) ClearSessionStore() {
	sdc.mu.Lock()
	defer sdc.mu.Unlock()

	sdc.sessionStore = make(map[string]sessionStoreEntry)
}
