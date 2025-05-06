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

const OAuth2ErrorPage = () => {
  const [errorCode, setErrorCode] = useState('N/A');
  const [errorMsg, setErrorMsg] = useState('No details provided');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setErrorCode(params.get('oauthErrorCode') || 'N/A');
    setErrorMsg(params.get('oauthErrorMsg') || 'No details provided');
  }, []);

  return (
    <div style={styles.body}>
      <div style={styles.container}>
        <div style={styles.appLogo}>⚠️</div>
        <h1 style={styles.heading}>Something Went Wrong!</h1>
        <table style={styles.table}>
          <tbody>
            <tr>
              <th style={styles.th}>Error Code</th>
              <td style={styles.td}>{errorCode}</td>
            </tr>
            <tr>
              <th style={styles.th}>Error Message</th>
              <td style={styles.td}>{errorMsg}</td>
            </tr>
          </tbody>
        </table>
        <div style={styles.footer}>
          <span style={styles.thunderLogo}>⚡</span>
          <span>Powered by Asgardeo Thunder</span>
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
    marginBottom: 20,
    color: '#FFA500',
  },
  table: {
    margin: '0 auto',
    borderCollapse: 'collapse',
    width: '100%',
  },
  th: {
    border: '1px solid #444',
    padding: 10,
    backgroundColor: '#333',
    color: '#FFA500',
  },
  td: {
    border: '1px solid #444',
    padding: 10,
    backgroundColor: '#1E1E2F',
    color: '#FFFFFF',
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

export default OAuth2ErrorPage;
