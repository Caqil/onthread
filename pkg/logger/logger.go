package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Logger levels
const (
	LevelTrace = "trace"
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
	LevelFatal = "fatal"
	LevelPanic = "panic"
)

// Context keys
type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	UserIDKey    contextKey = "user_id"
	AdminIDKey   contextKey = "admin_id"
	SessionIDKey contextKey = "session_id"
	TraceIDKey   contextKey = "trace_id"
)

// Logger represents the application logger
type Logger struct {
	*logrus.Logger
	component string
}

// Fields represents log fields
type Fields map[string]interface{}

var (
	defaultLogger *Logger
	logLevel      logrus.Level = logrus.InfoLevel
	logFormat     string       = "json" // "json" or "text"
)

// Config represents logger configuration
type Config struct {
	Level     string `json:"level"`
	Format    string `json:"format"`
	Output    string `json:"output"`
	Component string `json:"component"`
}

// Init initializes the default logger
func Init() {
	config := &Config{
		Level:     getEnv("LOG_LEVEL", LevelInfo),
		Format:    getEnv("LOG_FORMAT", "json"),
		Output:    getEnv("LOG_OUTPUT", "stdout"),
		Component: getEnv("LOG_COMPONENT", "thread-app"),
	}

	defaultLogger = NewLogger(config)
}

// NewLogger creates a new logger instance
func NewLogger(config *Config) *Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logLevel = level

	// Set log format
	if config.Format == "text" {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := strings.Split(f.File, "/")
				return f.Function, fmt.Sprintf("%s:%d", filename[len(filename)-1], f.Line)
			},
		})
		logFormat = "text"
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := strings.Split(f.File, "/")
				return f.Function, fmt.Sprintf("%s:%d", filename[len(filename)-1], f.Line)
			},
		})
		logFormat = "json"
	}

	// Set output
	switch config.Output {
	case "stdout":
		logger.SetOutput(os.Stdout)
	case "stderr":
		logger.SetOutput(os.Stderr)
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.SetOutput(os.Stdout)
			logger.Warnf("Failed to open log file %s, using stdout", config.Output)
		} else {
			logger.SetOutput(io.MultiWriter(os.Stdout, file))
		}
	}

	// Enable caller reporting
	logger.SetReportCaller(true)

	return &Logger{
		Logger:    logger,
		component: config.Component,
	}
}

// WithContext creates a logger with context values
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.Logger.WithFields(logrus.Fields{})

	if requestID := getStringFromContext(ctx, RequestIDKey); requestID != "" {
		entry = entry.WithField("request_id", requestID)
	}

	if userID := getStringFromContext(ctx, UserIDKey); userID != "" {
		entry = entry.WithField("user_id", userID)
	}

	if adminID := getStringFromContext(ctx, AdminIDKey); adminID != "" {
		entry = entry.WithField("admin_id", adminID)
	}

	if sessionID := getStringFromContext(ctx, SessionIDKey); sessionID != "" {
		entry = entry.WithField("session_id", sessionID)
	}

	if traceID := getStringFromContext(ctx, TraceIDKey); traceID != "" {
		entry = entry.WithField("trace_id", traceID)
	}

	if l.component != "" {
		entry = entry.WithField("component", l.component)
	}

	return entry
}

// WithFields creates a logger with additional fields
func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// WithField creates a logger with a single additional field
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithError creates a logger with an error field
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithComponent creates a logger with a component field
func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.Logger.WithField("component", component)
}

// WithUserID creates a logger with a user ID field
func (l *Logger) WithUserID(userID primitive.ObjectID) *logrus.Entry {
	return l.Logger.WithField("user_id", userID.Hex())
}

// WithAdminID creates a logger with an admin ID field
func (l *Logger) WithAdminID(adminID primitive.ObjectID) *logrus.Entry {
	return l.Logger.WithField("admin_id", adminID.Hex())
}

// WithRequestID creates a logger with a request ID field
func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.Logger.WithField("request_id", requestID)
}

// WithSessionID creates a logger with a session ID field
func (l *Logger) WithSessionID(sessionID string) *logrus.Entry {
	return l.Logger.WithField("session_id", sessionID)
}

// Trace logs a trace message
func (l *Logger) Trace(args ...interface{}) {
	l.Logger.Trace(args...)
}

// Tracef logs a trace message with formatting
func (l *Logger) Tracef(format string, args ...interface{}) {
	l.Logger.Tracef(format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

// Debugf logs a debug message with formatting
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

// Info logs an info message
func (l *Logger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

// Infof logs an info message with formatting
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(args ...interface{}) {
	l.Logger.Warn(args...)
}

// Warnf logs a warning message with formatting
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

// Error logs an error message
func (l *Logger) Error(args ...interface{}) {
	l.Logger.Error(args...)
}

// Errorf logs an error message with formatting
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(args ...interface{}) {
	l.Logger.Fatal(args...)
}

// Fatalf logs a fatal message with formatting and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(args ...interface{}) {
	l.Logger.Panic(args...)
}

// Panicf logs a panic message with formatting and panics
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.Logger.Panicf(format, args...)
}

// Package-level functions using the default logger
func WithContext(ctx context.Context) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithContext(ctx)
}

func WithFields(fields Fields) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithFields(fields)
}

func WithField(key string, value interface{}) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithField(key, value)
}

func WithError(err error) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithError(err)
}

func WithComponent(component string) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithComponent(component)
}

func WithUserID(userID primitive.ObjectID) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithUserID(userID)
}

func WithAdminID(adminID primitive.ObjectID) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithAdminID(adminID)
}

func WithRequestID(requestID string) *logrus.Entry {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger.WithRequestID(requestID)
}

func Trace(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Trace(args...)
}

func Tracef(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Tracef(format, args...)
}

func Debug(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Debugf(format, args...)
}

func Info(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Info(args...)
}

func Infof(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Infof(format, args...)
}

func Warn(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Warnf(format, args...)
}

func Error(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Error(args...)
}

func Errorf(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Errorf(format, args...)
}

func Fatal(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Fatal(args...)
}

func Fatalf(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Fatalf(format, args...)
}

func Panic(args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Panic(args...)
}

func Panicf(format string, args ...interface{}) {
	if defaultLogger == nil {
		Init()
	}
	defaultLogger.Panicf(format, args...)
}

// Utility functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getStringFromContext(ctx context.Context, key contextKey) string {
	if value := ctx.Value(key); value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// LogLevel returns the current log level
func LogLevel() string {
	return logLevel.String()
}

// LogFormat returns the current log format
func LogFormat() string {
	return logFormat
}

// SetLevel sets the log level
func SetLevel(level string) error {
	parsedLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}

	if defaultLogger != nil {
		defaultLogger.SetLevel(parsedLevel)
	}
	logLevel = parsedLevel
	return nil
}

// GetLogger returns the default logger
func GetLogger() *Logger {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger
}

// NewContextWithRequestID creates a new context with request ID
func NewContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// NewContextWithUserID creates a new context with user ID
func NewContextWithUserID(ctx context.Context, userID primitive.ObjectID) context.Context {
	return context.WithValue(ctx, UserIDKey, userID.Hex())
}

// NewContextWithAdminID creates a new context with admin ID
func NewContextWithAdminID(ctx context.Context, adminID primitive.ObjectID) context.Context {
	return context.WithValue(ctx, AdminIDKey, adminID.Hex())
}

// NewContextWithSessionID creates a new context with session ID
func NewContextWithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}

// LogRequest logs an HTTP request
func LogRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	WithContext(ctx).WithFields(logrus.Fields(Fields{
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
	})).Info("HTTP request")
}

// LogDatabaseQuery logs a database query
func LogDatabaseQuery(ctx context.Context, collection, operation string, duration time.Duration) {
	WithContext(ctx).WithFields(logrus.Fields{
		"collection":  collection,
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
	}).Debug("Database query")
}

// LogWebSocketEvent logs a WebSocket event
func LogWebSocketEvent(ctx context.Context, event string, userID primitive.ObjectID) {
	WithContext(ctx).WithFields(logrus.Fields{
		"event":   event,
		"user_id": userID.Hex(),
	}).Debug("WebSocket event")
}
