# Sample Client App

This is a sample React application that demonstrates the Thunder login flow. The application allows users to log in using their credentials and retrieves an access token from the server.

## Prerequisites

- Node 20+

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd thunder/samples/apps/oauth
   ```

2. Generate a self-signed SSL certificate by running the following command:
   ```bash
   openssl req -nodes -new -x509 -keyout server.key -out server.cert
   ```

3. **Install dependencies:**
   ```bash
   pnpm i
   ```

4. **Configure environment variables:**
   Create a `.env` file in the frontend sample directory if it doesn't exist, and add the following environment variables:

   ```env
   VITE_REACT_APPLICATIONS_ENDPOINT=https://localhost:8090/applications
   VITE_REACT_APP_SERVER_FLOW_ENDPOINT=https://localhost:8090/flow
   VITE_REACT_APP_BASIC_AUTH_APP_ID=<your-app-id>
   ```

5. **Run the application:**
   ```bash
   pnpm start
   ```

6. **Open the application in your browser:**
   Navigate to `https://localhost:3000`.
