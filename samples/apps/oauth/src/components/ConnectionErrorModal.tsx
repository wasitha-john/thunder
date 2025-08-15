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

import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import RefreshIcon from '@mui/icons-material/Refresh';
import { keyframes } from '@mui/system';
import { useEffect, useState, useCallback } from 'react';

interface ConnectionErrorModalProps {
    onRetry: () => void | Promise<unknown>;
    retryCount?: number;
    onRetryCountIncrement?: () => void;
}

// Define a rotation animation for the refresh icon
const spin = keyframes`
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
`;

/**
 * Component that appears when server connectivity issues are detected.
 */
const ConnectionErrorModal = ({ onRetry, retryCount = 0, onRetryCountIncrement }: ConnectionErrorModalProps) => {
    const [countdown, setCountdown] = useState<number>(5);
    const [retryStatus, setRetryStatus] = useState<'idle' | 'counting' | 'retrying'>('idle');
    const maxRetriesReached = retryCount > 3;

    // Use useCallback to memoize the handleRetryOperation function
    const handleRetryOperation = useCallback(() => {
        setRetryStatus('retrying');
        
        try {
            const result = onRetry();
            
            // Handle Promise-based or async retry function
            if (result && typeof result === 'object' && 'finally' in result) {
                (result as Promise<unknown>).finally(() => {
                    setRetryStatus('counting');
                });
            } else {
                // If not a Promise, set a short timeout to reset the state
                setTimeout(() => {
                    setRetryStatus('counting');
                }, 2000);
            }
        } catch {
            setRetryStatus('counting');
        }
    }, [onRetry]);

    // Handle automatic retry with countdown
    useEffect(() => {
        let timer: number;
        
        if (!maxRetriesReached && retryStatus === 'counting' && countdown > 0) {
            timer = window.setTimeout(() => {
                setCountdown(prev => prev - 1);
            }, 1000);
        } else if (!maxRetriesReached && retryStatus === 'counting' && countdown === 0) {
            setCountdown(5);
            handleRetryOperation();
            // Increment retry count for auto-retries
            if (onRetryCountIncrement) {
                onRetryCountIncrement();
            }
        }
        
        return () => {
            if (timer) clearTimeout(timer);
        };
    }, [retryStatus, countdown, handleRetryOperation, maxRetriesReached, onRetryCountIncrement]);

    // Start auto retry when component mounts (only if maxRetriesReached is false)
    useEffect(() => {
        if (!maxRetriesReached) {
            setRetryStatus('counting');
        }
        return () => setRetryStatus('idle');
    }, [maxRetriesReached]);

    const handleManualRetry = () => {
        if (retryStatus === 'counting') {
            // Reset countdown if manually retrying during auto countdown
            setCountdown(5);
        }
        handleRetryOperation();
    };

    // Derived values from the retryStatus
    const isRetrying = retryStatus === 'retrying';
    const isAutoRetrying = retryStatus === 'counting' && !maxRetriesReached;

    return (
        <Paper 
            elevation={2}
            sx={{ 
                overflow: 'hidden',
                borderRadius: 2,
                border: '1px solid',
                borderColor: 'error.light',
                mb: 3
            }}
        >
            <Alert 
                severity="error" 
                icon={false}
                sx={{ 
                    py: 2,
                    px: 3,
                    '& .MuiAlert-message': {
                        width: '100%'
                    }
                }}
            >
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', mb: 1 }}>
                    <AlertTitle sx={{ fontSize: '1.1rem', fontWeight: 500, m: 0 }}>
                        Connection Error
                    </AlertTitle>
                </Box>
                
                <Typography variant="body1" component={Box} sx={{ opacity: 0.9, my: 2, textAlign: 'center' }}>
                    Unable to connect to the authentication server. Please make sure the server is running.
                    {maxRetriesReached && (
                        <Box sx={{ mt: 1, fontWeight: 'medium', color: 'error.main' }}>
                            Maximum retry attempts reached.
                        </Box>
                    )}
                </Typography>
                
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mt: 3 }}>
                    {isAutoRetrying && (
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                            <Typography variant="body2">
                                Retrying in {countdown} second{countdown !== 1 ? 's' : ''}...
                            </Typography>
                        </Box>
                    )}
                    
                    <Button
                        variant="outlined"
                        color="error"
                        size="medium"
                        onClick={handleManualRetry}
                        disabled={isRetrying}
                        sx={{
                            minWidth: '120px',
                            borderRadius: 2,
                            '& .MuiSvgIcon-root': {
                                animation: isRetrying ? `${spin} 1.5s infinite linear` : 'none',
                            },
                        }}
                        startIcon={<RefreshIcon />}
                    >
                        {isRetrying ? 'Retrying...' : isAutoRetrying ? 'Retry Now' : 'Retry'}
                    </Button>
                </Box>
            </Alert>
        </Paper>
    );
};

export default ConnectionErrorModal;
