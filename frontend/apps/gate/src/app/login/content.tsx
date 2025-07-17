/**
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

'use client';

import Alert from '@oxygen-ui/react/src/components/Alert/Alert';
import Box from '@oxygen-ui/react/src/components/Box/Box';
import Button from '@oxygen-ui/react/src/components/Button/Button';
import OutlinedInput from '@oxygen-ui/react/src/components/OutlinedInput/OutlinedInput';
import InputLabel from '@oxygen-ui/react/src/components/InputLabel/InputLabel';
import Typography from '@oxygen-ui/react/src/components/Typography/Typography';
import React, { useState, useEffect, ReactElement } from 'react';
import axios from 'axios';
import AppConfig from '@/configs/app.json';

const LoginPageContent = function (): ReactElement {
  const [insecureWarning, setInsecureWarning] = useState<boolean>(false);
  const [flowId, setFlowId] = useState<string>('');
  const [inputs, setInputs] = useState<any[]>([]);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const params: URLSearchParams = new URLSearchParams(window.location.search);
    const key = params.get('sessionDataKey') || '';
    setInsecureWarning(params.get('showInsecureWarning') === 'true');
    if (key) {
      axios.post(AppConfig.authenticationEndpoint, { sessionDataKey: key }, {
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        withCredentials: true,
      })
        .then((res) => {
          setFlowId(res.data.flowId);
          setInputs(res.data.data?.inputs || []);
          setLoading(false);
        })
        .catch(() => {
          setError('Failed to initiate authentication flow.');
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormValues({ ...formValues, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const res = await axios.post(AppConfig.authenticationEndpoint, {
        flowId,
        inputs: formValues,
      }, {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true,
        validateStatus: () => true,
      });
      if (res.status === 302 && res.headers.location) {
        window.location.href = res.headers.location;
        return;
      }
      if (res.data.flowStatus === 'ERROR') {
        setError(res.data.failureReason || 'Authentication failed.');
      } else if (res.data.flowStatus === 'COMPLETE') {
        const redirectUrl = res.data.data.redirectURL;
        if (redirectUrl) {
          window.location.href = redirectUrl;
        } else {
          setError('Authentication completed but no redirect URL provided.');
        }
      } else if (res.data.flowStatus === 'INCOMPLETE') {
        setError('Authentication incomplete.');
      }
    } catch (err) {
      setError('Failed to authenticate.');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" gutterBottom>
          Login to Account
        </Typography>
      </Box>
      {insecureWarning && (
        <Alert severity="warning" sx={{ my: 2 }}>
          You are about to access a non-secure site. Proceed with caution!
        </Alert>
      )}
      {error && (
        <Alert severity="error" sx={{ my: 2 }}>{error}</Alert>
      )}
      {loading ? (
        <Typography>Loading...</Typography>
      ) : (
        <Box display="flex" flexDirection="column" gap={2}>
          {inputs.map((input) => (
            <Box key={input.name} display="flex" flexDirection="column" gap={0.5}>
              <InputLabel htmlFor={input.name}>{input.name.charAt(0).toUpperCase() + input.name.slice(1)}</InputLabel>
              <OutlinedInput
                type={input.type === 'password' ? 'password' : 'text'}
                id={input.name}
                name={input.name}
                placeholder={`Enter your ${input.name}`}
                size="small"
                required={input.required}
                value={formValues[input.name] || ''}
                onChange={handleInputChange}
              />
            </Box>
          ))}
          <Button variant="contained" color="primary" type="submit" fullWidth sx={{ mt: 2 }}>
            Sign In
          </Button>
        </Box>
      )}
    </form>
  );
};

export default LoginPageContent;
