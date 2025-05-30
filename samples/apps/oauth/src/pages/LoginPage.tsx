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

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Divider from '@mui/material/Divider';
import FormControlLabel from '@mui/material/FormControlLabel';
import Grid from '@mui/material/Grid';
import InputLabel from '@mui/material/InputLabel';
import OutlinedInput from '@mui/material/OutlinedInput';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';
import GoogleIcon from '@mui/icons-material/Google';
import GitHubIcon from '@mui/icons-material/GitHub';
import { useEffect, useRef, useState, useCallback } from 'react';
import Layout from '../components/Layout';
import { NativeAuthSubmitType, initiateNativeAuth, submitNativeAuth } from '../services/authService';
import { useAuth } from '../contexts/AuthContext';

/**
 * LoginPage component renders the login page with options for username/password login,
 * 
 * @param props LoginPageProps
 * @returns 
 */
const LoginPage = () => {

    const START_INIT_KEY = 'startInit';
    const FLOW_ID_KEY = 'flowId';

    const isComponentReMount = useRef(false);
    const { setToken, clearToken } = useAuth();

    const [showSignUp] = useState<boolean>(false);
    const [showGoogleLoginButton] = useState<boolean>(false);
    const [showRememberMe] = useState<boolean>(false);
    const [showForgotPassword] = useState<boolean>(false);
    const [error, setError] = useState<boolean>(false);

    const [flowId, setFlowId] = useState<string>(sessionStorage.getItem(FLOW_ID_KEY) || '');
    const [startInit] = useState<boolean>(JSON.parse(sessionStorage.getItem(START_INIT_KEY) || 'true'));

    const [userNamePasswordLogin, setUserNamePasswordLogin] = useState<boolean>(false);
    const [basicAuthFormData, setBasicAuthFormData] = useState({
        username: '',
        password: '',
    });

    const [showGitHubLoginButton, setShowGithubLoginButton] = useState<boolean>(false);
    const [gitHubRedirectURL, setGitHubRedirectURL] = useState<string>('');

    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const { name, value } = event.target;
        setBasicAuthFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleGitHubLoginClick = () => {
        sessionStorage.setItem(FLOW_ID_KEY, flowId);
        sessionStorage.setItem(START_INIT_KEY, "false");
        window.location.href = gitHubRedirectURL;
    };

    const init = useCallback(() => {
        clearToken();

        initiateNativeAuth()
            .then((result) => {
                if (result.data?.type === "VIEW") {
                    setUserNamePasswordLogin(true);
                }

                if (result.data?.type === "REDIRECTION") {
                    setShowGithubLoginButton(true);
                    setGitHubRedirectURL(result.data?.additionalInfo?.redirect_url);
                }
                
                setFlowId(result.data.flowId);
            }).catch((error) => {
                console.error("Error during authentication:", error);
            });
    }, [clearToken]);

    const handelBasicAuthSubmit = (event: React.SyntheticEvent) => {
        event.preventDefault();

        submitNativeAuth(flowId, { type: NativeAuthSubmitType.BASIC, ...basicAuthFormData })
            .then((result) => {
                const data = result.data;

                // Handle successful authentication
                if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                    setToken(data.assertion);
                    setError(false);
                }
            }).catch(() => {
                setError(true);

                init();
            });
    };

    // This effect is to handle initial component mount
    useEffect(() => {
        // Prevent double mount due to React Strict Mode
        if (isComponentReMount.current) return;
        isComponentReMount.current = true;

        if (startInit) {
            init();
        }
    },[startInit, init]);


    // This effect is to handle when return from GitHub login
    useEffect(() => {
        if (!startInit) {
            const params = new URLSearchParams(window.location.search);
            const code = params.get('code');

            if (code) {
                submitNativeAuth(flowId, { type: NativeAuthSubmitType.SOCIAL, code: code })
                    .then((result) => {
                        const data = result.data;

                        // Handle successful authentication
                        if (data.flowStatus && data.flowStatus === 'COMPLETE' && data.assertion) {
                            setToken(data.assertion);
                            setError(false);
                        }
                    }).catch(() => {
                        // setError(true);
                    });
            } else {
                setError(true);
            }

            sessionStorage.setItem(START_INIT_KEY, "true");
        }
    }, [flowId, setToken, startInit]);

    return (
        <Layout>
            <Grid size={{ xs: 12, md: 6 }}>
                <Paper
                    sx={{
                        display: "flex",
                        width: "100%",
                        height: "100%",
                        flexDirection: "column",
                    }}
                >
                    <Box
                        sx={{
                            alignItems: "center",
                            justifyContent: "center",
                            padding: 6,
                            width: "100%",
                            maxWidth: 500,
                            margin: "auto",
                        }}
                    >
                        <Box>
                            <Box sx={{ mb: 4 }}>
                                <Typography variant="h5" gutterBottom>
                                Login to Account
                                </Typography>

                                {showSignUp && (
                                <Typography>
                                    Don&apos;t have an account <Link href="">Sign up!</Link>
                                </Typography>
                                )}
                            </Box>

                            {error && (
                                <Alert severity="error" sx={{ my: 2 }}>
                                    Login failed. Please check your credentials.
                                </Alert>
                            )}

                            {(showGoogleLoginButton || showGitHubLoginButton) && (
                                <>
                                    <Box>
                                        {showGoogleLoginButton && (
                                            <Button
                                                fullWidth
                                                variant="contained"
                                                startIcon={<GoogleIcon />}
                                                color="secondary"
                                                sx={{ my: 1 }}
                                            >
                                                Continue with Google
                                            </Button>
                                        )}
                                        {showGitHubLoginButton && (
                                        <Button
                                            fullWidth
                                            variant="contained"
                                            startIcon={<GitHubIcon />}
                                            color="secondary"
                                            onClick={() => handleGitHubLoginClick()}
                                            sx={{ my: 1 }}
                                        >
                                            Continue with GitHub
                                        </Button>
                                        )}
                                    </Box>
                                    
                                    { userNamePasswordLogin &&
                                        <Divider sx={{ my: 3 }}>or</Divider>
                                    }
                                </>
                            )}

                            { userNamePasswordLogin &&
                                <Box display="flex" flexDirection="column" gap={2}>
                                    <Box display="flex" flexDirection="column" gap={0.5}>
                                        <InputLabel htmlFor="username">Username</InputLabel>
                                        <OutlinedInput
                                            type="text"
                                            id="username"
                                            name="username"
                                            placeholder="Enter your username"
                                            size="small"
                                            value={basicAuthFormData.username}
                                            onChange={handleInputChange}
                                            required
                                        />
                                    </Box>
                                    <Box display="flex" flexDirection="column" gap={0.5}>
                                        <InputLabel htmlFor="password">Password</InputLabel>
                                        <OutlinedInput
                                            type="password"
                                            id="password"
                                            name="password"
                                            placeholder="Enter your password"
                                            size="small"
                                            value={basicAuthFormData.password}
                                            onChange={handleInputChange}
                                            required
                                        />
                                    </Box>
                                    {(showRememberMe || showForgotPassword) && (
                                        <Box
                                            sx={{
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            alignItems: 'center',
                                            }}
                                        >
                                            {showRememberMe && (
                                                <FormControlLabel
                                                    control={<Checkbox name="remember-me-checkbox" />} 
                                                    label="Remember me" />
                                            )}
                                            {showForgotPassword && <Link href="">Forgot your password?</Link>}
                                        </Box>
                                    )}
                                    <Button
                                        variant="contained"
                                        color="primary"
                                        type="submit"
                                        fullWidth
                                        sx={{ mt: 2 }}
                                        onClick={(e) => handelBasicAuthSubmit(e)}
                                    >
                                        Sign In
                                    </Button>
                                </Box>
                            }
                            <Box component="footer" sx={{ mt: 6 }}>
                                <Typography sx={{ textAlign: "center" }}>
                                    © Copyright {new Date().getFullYear()}
                                </Typography>
                            </Box>
                        </Box>
                    </Box>
                </Paper>
            </Grid>
        </Layout>
    );
};

export default LoginPage;
