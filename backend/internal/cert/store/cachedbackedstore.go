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

package store

import (
	"errors"

	"github.com/asgardeo/thunder/internal/cert/constants"
	"github.com/asgardeo/thunder/internal/cert/model"
	"github.com/asgardeo/thunder/internal/system/cache"
	"github.com/asgardeo/thunder/internal/system/log"
)

const cachedStoreLoggerComponentName = "CachedBackedCertificateStore"

// CachedBackedCertificateStore is the implementation of CertificateStoreInterface that uses caching.
type CachedBackedCertificateStore struct {
	CertByIDCache        cache.CacheInterface[*model.Certificate]
	CertByReferenceCache cache.CacheInterface[*model.Certificate]
	Store                CertificateStoreInterface
}

// NewCachedBackedCertificateStore creates a new instance of CachedBackedCertificateStore.
func NewCachedBackedCertificateStore() CertificateStoreInterface {
	return &CachedBackedCertificateStore{
		CertByIDCache:        cache.GetCache[*model.Certificate]("CertificateByIDCache"),
		CertByReferenceCache: cache.GetCache[*model.Certificate]("CertificateByReferenceCache"),
		Store:                NewCertificateStore(),
	}
}

// GetCertificateByID retrieves a certificate by its ID, using cache if available.
func (s *CachedBackedCertificateStore) GetCertificateByID(id string) (*model.Certificate, error) {
	cacheKey := cache.CacheKey{
		Key: id,
	}
	cachedCert, ok := s.CertByIDCache.Get(cacheKey)
	if ok {
		return cachedCert, nil
	}

	cert, err := s.Store.GetCertificateByID(id)
	if err != nil || cert == nil {
		return cert, err
	}
	s.cacheCertificate(cert)

	return cert, nil
}

// GetCertificateByReference retrieves a certificate by its reference type and ID, using cache if available.
func (s *CachedBackedCertificateStore) GetCertificateByReference(refType constants.CertificateReferenceType,
	refID string) (*model.Certificate, error) {
	cacheKey := getCertByReferenceCacheKey(refType, refID)
	cachedCert, ok := s.CertByReferenceCache.Get(cacheKey)
	if ok {
		return cachedCert, nil
	}

	cert, err := s.Store.GetCertificateByReference(refType, refID)
	if err != nil || cert == nil {
		return cert, err
	}
	s.cacheCertificate(cert)

	return cert, nil
}

// CreateCertificate creates a new certificate and caches it.
func (s *CachedBackedCertificateStore) CreateCertificate(cert *model.Certificate) error {
	if err := s.Store.CreateCertificate(cert); err != nil {
		return err
	}
	s.cacheCertificate(cert)
	return nil
}

// UpdateCertificateByID updates an existing certificate by its ID and refreshes the cache.
func (s *CachedBackedCertificateStore) UpdateCertificateByID(existingCert, updatedCert *model.Certificate) error {
	if err := s.Store.UpdateCertificateByID(existingCert, updatedCert); err != nil {
		return err
	}

	// Invalidate old caches and cache the updated certificate
	s.invalidateCertificateCache(existingCert.ID, existingCert.RefType, existingCert.RefID)
	s.cacheCertificate(updatedCert)

	return nil
}

// UpdateCertificateByReference updates an existing certificate by its reference type and ID and refreshes the cache.
func (s *CachedBackedCertificateStore) UpdateCertificateByReference(existingCert,
	updatedCert *model.Certificate) error {
	if err := s.Store.UpdateCertificateByReference(existingCert, updatedCert); err != nil {
		return err
	}

	// Invalidate old caches and cache the updated certificate
	s.invalidateCertificateCache(existingCert.ID, existingCert.RefType, existingCert.RefID)
	s.cacheCertificate(updatedCert)

	return nil
}

// DeleteCertificateByID deletes a certificate by its ID and invalidates the caches.
func (s *CachedBackedCertificateStore) DeleteCertificateByID(id string) error {
	cacheKey := cache.CacheKey{
		Key: id,
	}
	existingCert, ok := s.CertByIDCache.Get(cacheKey)
	if !ok {
		var err error
		existingCert, err = s.Store.GetCertificateByID(id)
		if err != nil {
			if errors.Is(err, constants.ErrCertificateNotFound) {
				return nil
			}
			return err
		}
	}
	if existingCert == nil {
		return nil
	}

	if err := s.Store.DeleteCertificateByID(id); err != nil {
		return err
	}
	s.invalidateCertificateCache(existingCert.ID, existingCert.RefType, existingCert.RefID)

	return nil
}

// DeleteCertificateByReference deletes a certificate by its reference type and ID and invalidates the caches.
func (s *CachedBackedCertificateStore) DeleteCertificateByReference(refType constants.CertificateReferenceType,
	refID string) error {
	cacheKey := getCertByReferenceCacheKey(refType, refID)
	existingCert, ok := s.CertByReferenceCache.Get(cacheKey)
	if !ok {
		var err error
		existingCert, err = s.Store.GetCertificateByReference(refType, refID)
		if err != nil {
			if errors.Is(err, constants.ErrCertificateNotFound) {
				return nil
			}
			return err
		}
	}
	if existingCert == nil {
		return nil
	}

	if err := s.Store.DeleteCertificateByReference(refType, refID); err != nil {
		return err
	}
	s.invalidateCertificateCache(existingCert.ID, existingCert.RefType, existingCert.RefID)

	return nil
}

// cacheCertificate caches the certificate by ID and reference.
func (s *CachedBackedCertificateStore) cacheCertificate(cert *model.Certificate) {
	if cert == nil {
		return
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, cachedStoreLoggerComponentName))

	// Cache by ID
	if cert.ID != "" {
		idCacheKey := cache.CacheKey{
			Key: cert.ID,
		}
		if err := s.CertByIDCache.Set(idCacheKey, cert); err != nil {
			logger.Error("Failed to cache certificate by ID", log.Error(err),
				log.String("certID", cert.ID))
		} else {
			logger.Debug("Certificate cached by ID", log.String("certID", cert.ID))
		}
	}

	// Cache by reference type and ID
	if cert.RefType != "" && cert.RefID != "" {
		refCacheKey := getCertByReferenceCacheKey(cert.RefType, cert.RefID)
		if err := s.CertByReferenceCache.Set(refCacheKey, cert); err != nil {
			logger.Error("Failed to cache certificate by reference", log.Error(err),
				log.String("refType", string(cert.RefType)), log.String("refID", cert.RefID))
		} else {
			logger.Debug("Certificate cached by reference", log.String("refType", string(cert.RefType)),
				log.String("refID", cert.RefID))
		}
	}
}

// invalidateCertificateCache invalidates all certificate caches for the given ID and reference.
func (s *CachedBackedCertificateStore) invalidateCertificateCache(id string,
	refType constants.CertificateReferenceType, refID string) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, cachedStoreLoggerComponentName))

	// Invalidate ID cache
	if id != "" {
		idCacheKey := cache.CacheKey{
			Key: id,
		}
		if err := s.CertByIDCache.Delete(idCacheKey); err != nil {
			logger.Error("Failed to invalidate certificate cache by ID", log.Error(err),
				log.String("certID", id))
		} else {
			logger.Debug("Certificate cache invalidated by ID", log.String("certID", id))
		}
	}

	// Invalidate reference cache
	if refType != "" && refID != "" {
		refCacheKey := getCertByReferenceCacheKey(refType, refID)
		if err := s.CertByReferenceCache.Delete(refCacheKey); err != nil {
			logger.Error("Failed to invalidate certificate cache by reference", log.Error(err),
				log.String("refType", string(refType)), log.String("refID", refID))
		} else {
			logger.Debug("Certificate cache invalidated by reference", log.String("refType", string(refType)),
				log.String("refID", refID))
		}
	}
}

// getCertByReferenceCacheKey generates a cache key for a certificate based on its reference type and ID.
func getCertByReferenceCacheKey(refType constants.CertificateReferenceType, refID string) cache.CacheKey {
	return cache.CacheKey{
		Key: string(refType) + ":" + refID,
	}
}
