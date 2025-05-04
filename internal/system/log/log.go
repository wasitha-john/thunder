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

package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

// InitLogger initializes the logger with a plain text format.
func InitLogger() error {
	// Define a custom encoder configuration for plain text logs
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder, // INFO, ERROR, etc.
		EncodeTime:     zapcore.ISO8601TimeEncoder,  // Human-readable timestamps
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder, // Short file paths
	}

	// Create a core that writes logs to standard output with the custom encoder
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig), // Plain text encoder
		zapcore.AddSync(zapcore.Lock(os.Stdout)), // Write to standard output
		zapcore.InfoLevel,                        // Log level
	)

	// Build the logger
	logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	return nil
}

// GetLogger returns the initialized logger instance.
func GetLogger() *zap.Logger {

	if logger == nil {
		panic("Logger is not initialized. Call InitLogger() before using the logger.")
	}
	return logger
}

// Sync flushes any buffered log entries.
func Sync() {

	if logger != nil {
		_ = logger.Sync()
	}
}
