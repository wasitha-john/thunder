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

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';

/**
 * AuthContext provides authentication state management for the application.
 * It allows components to access the current authentication token and provides methods
 * to set and clear the token.
 */
type AuthContextType = {
  token: string | null;
  setToken: React.Dispatch<React.SetStateAction<string | null>>;
  clearToken: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * AuthProvider component to manage authentication state.
 * 
 * @param param0 - The children components to be wrapped by the AuthProvider.
 * @returns 
 */
export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem('authToken'));

  useEffect(() => {
    if (token === null) {
      sessionStorage.removeItem('authToken');
    } else {
      sessionStorage.setItem('authToken', token);
    }
  }, [token]);

  const clearToken = useCallback(() => setToken(null), []);

  return (
    <AuthContext.Provider value={{ token, setToken, clearToken }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to consume the AuthContext easily
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
