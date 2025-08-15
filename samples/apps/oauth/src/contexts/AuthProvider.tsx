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

import { useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import AuthContext from './AuthContext';

/**
 * AuthProvider component to manage authentication state.
 * 
 * @param children - The children components to be wrapped by the AuthProvider.
 * @returns 
 */
const AuthProvider = ({ children }: { children: ReactNode }) => {
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

export default AuthProvider;
