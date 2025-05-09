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

import React, { useEffect, useState } from 'react';

const LoginPage = () => {
  const [sessionDataKey, setSessionDataKey] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setSessionDataKey(params.get('sessionDataKey') || '');
  }, []);

  return (
    <div style={styles.body}>
      <div style={styles.container}>
        <div style={styles.appLogo}>🔐</div>
        <h1 style={styles.heading}>Login to Application</h1>
        <form method="POST" action="https://localhost:8090/flow/authn" style={styles.form}>
          <label htmlFor="username">Username:</label>
          <input type="text" id="username" name="username" placeholder="Enter username" required style={styles.input} />
          <label htmlFor="password">Password:</label>
          <input type="password" id="password" name="password" placeholder="Enter password" required style={styles.input} />
          <input type="hidden" id="sessionDataKey" name="sessionDataKey" value={sessionDataKey} />
          <button type="submit" style={styles.button}>Login</button>
        </form>
        <div style={styles.footer}>
          <span style={styles.thunderLogo}>⚡</span>
          <span>Powered by WSO2 Thunder</span>
        </div>
      </div>
    </div>
  );
};

const styles = {
  body: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh',
    margin: 0,
    fontFamily: 'Arial, sans-serif',
    backgroundColor: '#1E1E2F',
    color: '#FFFFFF',
  },
  container: {
    textAlign: 'center',
    background: '#2A2A40',
    padding: 40,
    borderRadius: 8,
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
  },
  appLogo: {
    fontSize: 60,
    marginBottom: 20,
    color: '#FFA500',
  },
  heading: {
    color: '#FFA500',
    marginBottom: 20,
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: 10,
  },
  input: {
    padding: 10,
    fontSize: 16,
    border: '1px solid #444',
    borderRadius: 4,
    backgroundColor: '#1E1E2F',
    color: '#FFFFFF',
  },
  button: {
    padding: 10,
    fontSize: 16,
    backgroundColor: '#FFA500',
    color: '#1E1E2F',
    border: 'none',
    borderRadius: 4,
    cursor: 'pointer',
    fontWeight: 'bold',
    marginTop: 20,
  },
  thunderLogo: {
    fontSize: 20,
    marginBottom: 20,
    color: '#FFA500',
    marginRight: 5,
  },
  footer: {
    marginTop: 30,
    fontSize: 14,
  },
};

export default LoginPage;
