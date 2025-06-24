package middleware

import (
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"onthread/pkg/logger"
)

// LoggingMiddleware handles request/response logging
type LoggingMiddleware struct {
	config *LoggingConfig
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	SkipPaths       []string // Paths to skip logging
	SkipUserAgents  []string // User agents to skip logging
	LogRequestBody  bool     // Whether to log request body
	LogResponseBody bool     // Whether to log response body
	MaxBodySize     int64    // Maximum body size to log (in bytes)
	SensitiveFields []string // Fields to redact in logs
}

// responseWriter wraps gin.ResponseWriter to capture response body
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// NewLoggingMiddleware creates a new logging middleware instance
func NewLoggingMiddleware() *LoggingMiddleware {
	return &LoggingMiddleware{
		config: DefaultLoggingConfig(),
	}
}

// NewLoggingMiddlewareWithConfig creates a new logging middleware with custom config
func NewLoggingMiddlewareWithConfig(config *LoggingConfig) *LoggingMiddleware {
	if config == nil {
		config = DefaultLoggingConfig()
	}
	return &LoggingMiddleware{
		config: config,
	}
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		SkipPaths: []string{
			"/health",
			"/ping",
			"/metrics",
			"/favicon.ico",
			"/robots.txt",
		},
		SkipUserAgents: []string{
			"kube-probe",
			"Prometheus",
			"ELB-HealthChecker",
		},
		LogRequestBody:  false,
		LogResponseBody: false,
		MaxBodySize:     1024 * 10, // 10KB
		SensitiveFields: []string{
			"password",
			"token",
			"secret",
			"key",
			"authorization",
			"cookie",
		},
	}
}

// LogRequests returns middleware that logs HTTP requests
func (m *LoggingMiddleware) LogRequests() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Skip logging for specified paths
		if m.shouldSkip(path, c.GetHeader("User-Agent")) {
			c.Next()
			return
		}

		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header("X-Request-ID", requestID)
		}

		// Add request ID to context
		ctx := logger.NewContextWithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Set("request_id", requestID)

		// Capture request body if enabled
		var requestBody string
		if m.config.LogRequestBody && c.Request.ContentLength > 0 && c.Request.ContentLength <= m.config.MaxBodySize {
			requestBody = m.captureRequestBody(c)
		}

		// Wrap response writer to capture response body
		var responseBody *bytes.Buffer
		if m.config.LogResponseBody {
			responseBody = &bytes.Buffer{}
			c.Writer = &responseWriter{
				ResponseWriter: c.Writer,
				body:           responseBody,
			}
		}

		// Process request
		c.Next()

		// Calculate metrics
		duration := time.Since(start)
		statusCode := c.Writer.Status()
		responseSize := c.Writer.Size()
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Prepare log fields
		fields := logrus.Fields{
			"method":        method,
			"path":          path,
			"status_code":   statusCode,
			"duration_ms":   duration.Milliseconds(),
			"response_size": responseSize,
			"client_ip":     clientIP,
			"user_agent":    userAgent,
			"request_id":    requestID,
		}

		// Add query parameters if present
		if c.Request.URL.RawQuery != "" {
			fields["query"] = c.Request.URL.RawQuery
		}

		// Add request body if captured
		if requestBody != "" {
			fields["request_body"] = m.sanitizeBody(requestBody)
		}

		// Add response body if captured
		if responseBody != nil && responseBody.Len() > 0 && responseBody.Len() <= int(m.config.MaxBodySize) {
			fields["response_body"] = m.sanitizeBody(responseBody.String())
		}

		// Add user info if available
		if userID, exists := c.Get("user_id"); exists {
			fields["user_id"] = userID
		}

		if adminID, exists := c.Get("admin_id"); exists {
			fields["admin_id"] = adminID
		}

		// Add error info if present
		if len(c.Errors) > 0 {
			fields["errors"] = c.Errors.String()
		}

		// Log with appropriate level based on status code
		logEntry := logger.WithContext(ctx).WithFields(fields)

		switch {
		case statusCode >= 500:
			logEntry.Error("HTTP request completed with server error")
		case statusCode >= 400:
			logEntry.Warn("HTTP request completed with client error")
		case statusCode >= 300:
			logEntry.Info("HTTP request completed with redirect")
		default:
			logEntry.Info("HTTP request completed")
		}
	}
}

// RequestID returns middleware that generates and sets request IDs
func (m *LoggingMiddleware) RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)

		// Add to request context
		ctx := logger.NewContextWithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// ErrorLogger returns middleware that logs errors
func (m *LoggingMiddleware) ErrorLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log any errors that occurred
		for _, err := range c.Errors {
			logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
				"error":      err.Error(),
				"error_type": err.Type,
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
			}).Error("Request error")
		}
	}
}

// SlowRequestLogger returns middleware that logs slow requests
func (m *LoggingMiddleware) SlowRequestLogger(threshold time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		duration := time.Since(start)
		if duration > threshold {
			logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
				"method":      c.Request.Method,
				"path":        c.Request.URL.Path,
				"duration_ms": duration.Milliseconds(),
				"threshold":   threshold.Milliseconds(),
			}).Warn("Slow request detected")
		}
	}
}

// AccessLogger returns middleware for access logging (simplified format)
func (m *LoggingMiddleware) AccessLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Skip logging for specified paths
		if m.shouldSkip(c.Request.URL.Path, c.GetHeader("User-Agent")) {
			c.Next()
			return
		}

		c.Next()

		// Log in Apache Common Log Format
		duration := time.Since(start)
		logger.WithContext(c.Request.Context()).Infof(
			"%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" %.3fms",
			c.ClientIP(),
			start.Format("02/Jan/2006:15:04:05 -0700"),
			c.Request.Method,
			c.Request.URL.Path,
			c.Request.Proto,
			c.Writer.Status(),
			c.Writer.Size(),
			c.GetHeader("Referer"),
			c.GetHeader("User-Agent"),
			float64(duration.Nanoseconds())/1e6,
		)
	}
}

// Helper methods

// shouldSkip determines if logging should be skipped for the request
func (m *LoggingMiddleware) shouldSkip(path, userAgent string) bool {
	// Check skip paths
	for _, skipPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	// Check skip user agents
	for _, skipUA := range m.config.SkipUserAgents {
		if strings.Contains(userAgent, skipUA) {
			return true
		}
	}

	return false
}

// captureRequestBody captures the request body for logging
func (m *LoggingMiddleware) captureRequestBody(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}

	// Read body
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return ""
	}

	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return string(bodyBytes)
}

// sanitizeBody removes sensitive information from request/response bodies
func (m *LoggingMiddleware) sanitizeBody(body string) string {
	sanitized := body

	// Replace sensitive fields (basic implementation)
	for _, field := range m.config.SensitiveFields {
		patterns := []string{
			`"` + field + `"\s*:\s*"[^"]*"`,  // JSON string values
			`"` + field + `"\s*:\s*[^,}\]]+`, // JSON non-string values
			field + `=[^&\s]*`,               // URL encoded values
		}

		for _, pattern := range patterns {
			// Simple replacement - in production, consider using regex
			if strings.Contains(strings.ToLower(sanitized), strings.ToLower(field)) {
				sanitized = strings.ReplaceAll(sanitized, pattern, field+":[REDACTED]")
			}
		}
	}

	return sanitized
}

// Utility functions for common logging scenarios

// LogAPIMetrics logs API performance metrics
func LogAPIMetrics(c *gin.Context, customFields logrus.Fields) {
	fields := logrus.Fields{
		"endpoint":      c.Request.URL.Path,
		"method":        c.Request.Method,
		"status_code":   c.Writer.Status(),
		"response_size": c.Writer.Size(),
	}

	// Merge custom fields
	for k, v := range customFields {
		fields[k] = v
	}

	logger.WithContext(c.Request.Context()).WithFields(fields).Info("API metrics")
}

// LogBusinessEvent logs business-related events
func LogBusinessEvent(c *gin.Context, event string, entityType string, entityID string, details logrus.Fields) {
	fields := logrus.Fields{
		"event":       event,
		"entity_type": entityType,
		"entity_id":   entityID,
	}

	// Merge details
	for k, v := range details {
		fields[k] = v
	}

	logger.WithContext(c.Request.Context()).WithFields(fields).Info("Business event")
}

// LogSecurityEvent logs security-related events
func LogSecurityEvent(c *gin.Context, event string, severity string, details logrus.Fields) {
	fields := logrus.Fields{
		"security_event": event,
		"severity":       severity,
		"client_ip":      c.ClientIP(),
		"user_agent":     c.GetHeader("User-Agent"),
	}

	// Merge details
	for k, v := range details {
		fields[k] = v
	}

	logEntry := logger.WithContext(c.Request.Context()).WithFields(fields)

	switch severity {
	case "critical", "high":
		logEntry.Error("Security event")
	case "medium":
		logEntry.Warn("Security event")
	default:
		logEntry.Info("Security event")
	}
}
