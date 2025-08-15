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
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package testutils

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	TargetDir                   = "../../target/dist"
	ExtractedDir                = "../../target/out/.test"
	ServerBinary                = "thunder"
	TestDeploymentYamlPath      = "./resources/deployment.yaml"
	TestDatabaseSchemaDirectory = "resources/dbscripts"
	TestGraphsDirectory         = "resources/graphs"
	InitScriptPath              = "./scripts/init_script.sh"
	DBScriptPath                = "./scripts/setup_db.sh"
	DatabaseFileBasePath        = "repository/database/"
)

func UnzipProduct(zipFilePattern string) error {
	// Find the zip file.
	files, err := findMatchingZipFile(zipFilePattern)
	if err != nil || len(files) == 0 {
		return fmt.Errorf("zip file not found in target directory")
	}

	// Unzip the file
	zipFile := files[0]
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(ExtractedDir, os.ModePerm)
	for _, f := range r.File {
		err := extractFile(f, ExtractedDir)
		if err != nil {
			return err
		}
	}

	// Set executable permissions for the server binary
	productHome, err := getExtractedProductHome(zipFilePattern)
	if err != nil {
		return err
	}
	serverPath := filepath.Join(productHome, ServerBinary)
	if err := os.Chmod(serverPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions for server binary: %v", err)
	}

	return nil
}

func extractFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	path := filepath.Join(dest, f.Name)
	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, os.ModePerm)
	}

	os.MkdirAll(filepath.Dir(path), os.ModePerm)
	outFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)

	return err
}

// getExtractedProductHome constructs the path to the unzipped folder.
func getExtractedProductHome(zipFilePattern string) (string, error) {
	files, err := findMatchingZipFile(zipFilePattern)
	if err != nil || len(files) == 0 {
		return "", fmt.Errorf("zip file not found in target directory")
	}
	zipFile := files[0]

	return filepath.Join(ExtractedDir, filepath.Base(zipFile[:len(zipFile)-4])), nil
}

// findMatchingZipFile finds zip files that match our specific version pattern criteria
func findMatchingZipFile(zipFilePattern string) ([]string, error) {
	path := filepath.Join(TargetDir, zipFilePattern)
	files, err := filepath.Glob(path)
	if err != nil {
		return nil, err
	}

	// Filter the files to only include those that have a version number or 'v' after 'thunder-'
	var matchingFiles []string
	for _, file := range files {
		baseName := filepath.Base(file)
		parts := strings.Split(baseName, "-")
		if len(parts) >= 3 {
			// Check if the second part starts with a number or 'v'
			secondPart := parts[1]
			if len(secondPart) > 0 && (secondPart[0] == 'v' || (secondPart[0] >= '0' && secondPart[0] <= '9')) {
				matchingFiles = append(matchingFiles, file)
			}
		}
	}

	return matchingFiles, nil
}

func ReplaceResources(zipFilePattern string) error {
	log.Println("Replacing resources...")

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting current directory: %v", err)
	} else {
		log.Printf("Current working directory: %s", cwd)
	}

	productHome, err := getExtractedProductHome(zipFilePattern)
	if err != nil {
		return err
	}

	destPath := filepath.Join(productHome, "repository/conf/deployment.yaml")
	err = copyFile(TestDeploymentYamlPath, destPath)
	if err != nil {
		return fmt.Errorf("failed to replace deployment.yaml: %v", err)
	}

	destPath = filepath.Join(productHome, "dbscripts")
	err = copyDirectory(TestDatabaseSchemaDirectory, destPath)
	if err != nil {
		return fmt.Errorf("failed to replace database schema files: %v", err)
	}

	// copy graphs from the target directory to the product home
	graphsDestPath := filepath.Join(productHome, "repository", "resources", "graphs")
	err = copyDirectory(TestGraphsDirectory, graphsDestPath)
	if err != nil {
		return fmt.Errorf("failed to replace graph files: %v", err)
	}

	return nil
}

func copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)

	return err
}

func copyDirectory(src, dest string) error {
	srcDir, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcDir.Close()

	entries, err := srcDir.Readdir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		destPath := filepath.Join(dest, entry.Name())

		if entry.IsDir() {
			err = os.MkdirAll(destPath, os.ModePerm)
			if err != nil {
				return err
			}
			err = copyDirectory(srcPath, destPath)
			if err != nil {
				return err
			}
		} else {
			err = copyFile(srcPath, destPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func RunInitScript(zipFilePattern string) error {
	log.Println("Running init script...")

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting current directory: %v", err)
	} else {
		log.Printf("Current working directory: %s", cwd)
	}

	productHome, err := getExtractedProductHome(zipFilePattern)
	if err != nil {
		return err
	}

	// Create databases.
	initScript := filepath.Join(productHome, InitScriptPath)

	// Create the thunderdb database.
	thunderDBSchemaPath := filepath.Join(productHome, "dbscripts/thunderdb", "sqlite.sql")
	thunderDbPath := filepath.Join(productHome, DatabaseFileBasePath, "thunderdb.db")
	cmd := exec.Command("bash", initScript, "-recreate", "-type", "sqlite", "-schema", thunderDBSchemaPath,
		"-path", thunderDbPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run init script for thunderdb: %v", err)
	}

	// Create the runtimedb database.
	runtimeDBSchemaPath := filepath.Join(productHome, "dbscripts/runtimedb", "sqlite.sql")
	runtimeDbPath := filepath.Join(productHome, DatabaseFileBasePath, "runtimedb.db")
	cmd = exec.Command("bash", initScript, "-recreate", "-type", "sqlite", "-schema", runtimeDBSchemaPath,
		"-path", runtimeDbPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run init script for runtimedb: %v", err)
	}

	return nil
}

func StartServer(port string, zipFilePattern string) (*exec.Cmd, error) {
	log.Println("Starting server...")
	productHome, err := getExtractedProductHome(zipFilePattern)
	if err != nil {
		return nil, err
	}
	serverPath := filepath.Join(productHome, ServerBinary)
	cmd := exec.Command(serverPath, "-thunderHome="+productHome)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PORT="+port)
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start server: %v", err)
	}

	return cmd, nil
}

func StopServer(cmd *exec.Cmd) {
	log.Println("Stopping server...")
	if cmd != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}

func GetZipFilePattern() string {
	goos, goarch := detectOSAndArchitecture()
	// Use a more general pattern, the filtering will happen in findMatchingZipFile
	return fmt.Sprintf("thunder-*-%s-%s.zip", goos, goarch)
}

// detectOSAndArchitecture detects the OS and architecture using Go environment variables
// or falls back to system detection if environment variables are not available
func detectOSAndArchitecture() (string, string) {
	// Try to get from environment variables first
	goos := os.Getenv("GOOS")
	goarch := os.Getenv("GOARCH")

	// If GOOS is not set, try to detect from system
	if goos == "" {
		// Try using go env command first
		cmd := exec.Command("go", "env", "GOOS")
		output, err := cmd.Output()
		if err == nil {
			goos = strings.TrimSpace(string(output))
		}

		// Fallback to uname if go env didn't work
		if goos == "" {
			cmd := exec.Command("uname", "-s")
			output, err := cmd.Output()
			if err == nil {
				osName := strings.TrimSpace(string(output))
				switch {
				case osName == "Darwin":
					goos = "darwin"
				case osName == "Linux":
					goos = "linux"
				case strings.HasPrefix(osName, "MINGW") ||
					strings.HasPrefix(osName, "MSYS") ||
					strings.HasPrefix(osName, "CYGWIN"):
					goos = "windows"
				}
			}
		}
	}

	// If GOARCH is not set, try to detect from system
	if goarch == "" {
		// Try using go env command first
		cmd := exec.Command("go", "env", "GOARCH")
		output, err := cmd.Output()
		if err == nil {
			goarch = strings.TrimSpace(string(output))
		}

		// Fall back to uname if go env didn't work
		if goarch == "" {
			cmd := exec.Command("uname", "-m")
			output, err := cmd.Output()
			if err == nil {
				arch := strings.TrimSpace(string(output))
				switch arch {
				case "x86_64", "amd64":
					goarch = "amd64"
				case "arm64", "aarch64":
					goarch = "arm64"
				}
			}
		}
	}

	// Normalize OS name according to distribution packaging
	if goos == "darwin" {
		goos = "macos"
	} else if goos == "windows" {
		goos = "win"
	}

	// Normalize architecture
	if goarch == "amd64" {
		goarch = "x64"
	}

	return goos, goarch
}
