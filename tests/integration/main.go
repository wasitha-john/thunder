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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/asgardeo/thunder/tests/integration/testutils"
)

const (
	serverPort = "8095"
)

var zipFilePattern string

func main() {
	initTests()

	// Step 1: Unzip the product
	err := testutils.UnzipProduct(zipFilePattern)
	if err != nil {
		fmt.Printf("Failed to unzip product: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Replace the resource files in the unzipped directory.
	err = testutils.ReplaceResources(zipFilePattern)
	if err != nil {
		fmt.Printf("Failed to replace resources: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Run the init script to create the SQLite database
	err = testutils.RunInitScript(zipFilePattern)
	if err != nil {
		fmt.Printf("Failed to run init script: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Start the server
	serverCmd, err := testutils.StartServer(serverPort, zipFilePattern)
	if err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		os.Exit(1)
	}
	defer testutils.StopServer(serverCmd)

	// Wait for the server to start
	fmt.Println("Waiting for the server to start...")
	time.Sleep(5 * time.Second)

	// Step 5: Run all tests
	err = runTests()
	if err != nil {
		fmt.Printf("there are test failures: %v\n", err)
		testutils.StopServer(serverCmd)
		os.Exit(1)
	}
}

func initTests() {
	zipFilePattern = testutils.GetZipFilePattern()
	if zipFilePattern == "" {
		fmt.Println("Failed to determine the zip file pattern.")
		os.Exit(1)
	}
	fmt.Printf("Using zip file pattern: %s\n", zipFilePattern)
}

func runTests() error {
	// Clean the test cache to avoid getting results from previous runs.
	// This is important to avoid false positives in test results as the
	// server and integration test suite are two separate applications.
	cmd := exec.Command("go", "clean", "-testcache")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to clean test cache: %w", err)
	}

	_, err = exec.LookPath("gotestsum")
	if err == nil {
		fmt.Println("Running integration tests using gotestsum...")
		cmd = exec.Command("gotestsum", "--format", "testname", "--", "-p=1", "./...")
	} else {
		fmt.Println("Running integration tests using go test...")
		cmd = exec.Command("go", "test", "-p=1", "-v", "./...")
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
