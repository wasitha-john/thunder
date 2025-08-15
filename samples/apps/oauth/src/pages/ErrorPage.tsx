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
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import Layout from '../components/Layout';

const ErrorPage = ({ errorCode, errorMessage }: { errorCode: string, errorMessage: string }) => {
    return (
        <Layout>
            <Box sx={{ width: '100%' }}>
                <Alert severity="error">
                    <AlertTitle sx={{ mb: 2 }}>Something didn&apos;t go as expected!</AlertTitle>
                    <Typography variant="body1" sx={{ mt: 3 }}>
                        {errorMessage}
                    </Typography>
                    {errorCode !== '' && (
                        <Typography variant="body1" sx={{ mt: 2 }}>
                        Error Code: {errorCode}
                        </Typography>
                    )}
                </Alert>
                <Box sx={{ mt: 4 }}>
                    <Button variant="contained" color="primary" onClick={() => window.location.href = '/'}>
                        Back to Login
                    </Button>
                </Box>
            </Box>
        </Layout>
    );
};

export default ErrorPage;
