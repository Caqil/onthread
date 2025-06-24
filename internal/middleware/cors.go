package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"onthread/internal/config"
	"onthread/pkg/logger"
)

// CorsMiddleware handles Cross-Origin Resource Sharing (CORS)
type CorsMiddleware struct {
	config *CorsConfig
}

// CorsConfig contains CORS configuration
type CorsConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
	OptionsResponse  bool
}

// NewCorsMiddleware creates a new CORS middleware instance
func NewCorsMiddleware() *CorsMiddleware {
	return &CorsMiddleware{
		config: DefaultCorsConfig(),
	}
}

// NewCorsMiddlewareWithConfig creates a new CORS middleware with custom config
func NewCorsMiddlewareWithConfig(config *CorsConfig) *CorsMiddleware {
	if config == nil {
		config = DefaultCorsConfig()
	}
	return &CorsMiddleware{
		config: config,
	}
}

// DefaultCorsConfig returns default CORS configuration
func DefaultCorsConfig() *CorsConfig {
	return &CorsConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
			"X-Session-ID",
			"X-API-Key",
			"X-Client-Version",
			"User-Agent",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"X-Request-ID",
			"X-Rate-Limit-Remaining",
			"X-Rate-Limit-Reset",
			"X-Rate-Limit-Limit",
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
		OptionsResponse:  true,
	}
}

// ProductionCorsConfig returns production-safe CORS configuration
func ProductionCorsConfig(allowedOrigins []string) *CorsConfig {
	config := DefaultCorsConfig()
	config.AllowOrigins = allowedOrigins
	return config
}

// DevelopmentCorsConfig returns development-friendly CORS configuration
func DevelopmentCorsConfig() *CorsConfig {
	config := DefaultCorsConfig()
	config.AllowOrigins = []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
	}
	return config
}

// Handler returns the CORS middleware handler
func (m *CorsMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		method := c.Request.Method

		// Set CORS headers
		m.setCorsHeaders(c, origin)

		// Handle preflight requests
		if method == http.MethodOptions && m.config.OptionsResponse {
			m.handlePreflight(c)
			return
		}

		// Continue with the request
		c.Next()
	}
}

// setCorsHeaders sets the appropriate CORS headers
func (m *CorsMiddleware) setCorsHeaders(c *gin.Context, origin string) {
	// Set Access-Control-Allow-Origin
	if m.isOriginAllowed(origin) {
		if len(m.config.AllowOrigins) == 1 && m.config.AllowOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
		}
	}

	// Set Access-Control-Allow-Credentials
	if m.config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}

	// Set Access-Control-Allow-Methods
	if len(m.config.AllowMethods) > 0 {
		c.Header("Access-Control-Allow-Methods", strings.Join(m.config.AllowMethods, ", "))
	}

	// Set Access-Control-Allow-Headers
	if len(m.config.AllowHeaders) > 0 {
		c.Header("Access-Control-Allow-Headers", strings.Join(m.config.AllowHeaders, ", "))
	}

	// Set Access-Control-Expose-Headers
	if len(m.config.ExposeHeaders) > 0 {
		c.Header("Access-Control-Expose-Headers", strings.Join(m.config.ExposeHeaders, ", "))
	}

	// Set Access-Control-Max-Age
	if m.config.MaxAge > 0 {
		c.Header("Access-Control-Max-Age", strconv.Itoa(int(m.config.MaxAge.Seconds())))
	}
}

// handlePreflight handles OPTIONS preflight requests
func (m *CorsMiddleware) handlePreflight(c *gin.Context) {
	// Log preflight request
	logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
		"origin":       c.GetHeader("Origin"),
		"method":       c.GetHeader("Access-Control-Request-Method"),
		"headers":      c.GetHeader("Access-Control-Request-Headers"),
		"user_agent":   c.GetHeader("User-Agent"),
		"request_type": "preflight",
	}).Debug("CORS preflight request")

	c.Status(http.StatusNoContent)
}

// isOriginAllowed checks if the origin is allowed
func (m *CorsMiddleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	// Check if wildcard is allowed
	for _, allowedOrigin := range m.config.AllowOrigins {
		if allowedOrigin == "*" {
			return true
		}
		if allowedOrigin == origin {
			return true
		}
		// Support for subdomain wildcards (e.g., *.example.com)
		if strings.HasPrefix(allowedOrigin, "*.") {
			domain := strings.TrimPrefix(allowedOrigin, "*.")
			if strings.HasSuffix(origin, "."+domain) || origin == domain {
				return true
			}
		}
	}

	return false
}

// StrictCors returns a strict CORS middleware for production
func StrictCors(allowedOrigins []string) gin.HandlerFunc {
	middleware := NewCorsMiddlewareWithConfig(ProductionCorsConfig(allowedOrigins))
	return middleware.Handler()
}

// PermissiveCors returns a permissive CORS middleware for development
func PermissiveCors() gin.HandlerFunc {
	middleware := NewCorsMiddlewareWithConfig(DevelopmentCorsConfig())
	return middleware.Handler()
}

// ConfigFromEnv creates CORS config from environment variables
func ConfigFromEnv(cfg *config.Config) *CorsConfig {
	corsConfig := DefaultCorsConfig()

	// Override with environment-specific settings
	if cfg.CORS.AllowedOrigins != nil {
		corsConfig.AllowOrigins = cfg.CORS.AllowedOrigins
	}

	if cfg.CORS.AllowedMethods != nil {
		corsConfig.AllowMethods = cfg.CORS.AllowedMethods
	}

	if cfg.CORS.AllowedHeaders != nil {
		corsConfig.AllowHeaders = cfg.CORS.AllowedHeaders
	}

	if cfg.CORS.ExposedHeaders != nil {
		corsConfig.ExposeHeaders = cfg.CORS.ExposedHeaders
	}

	corsConfig.AllowCredentials = cfg.CORS.AllowCredentials

	if cfg.CORS.MaxAge > 0 {
		corsConfig.MaxAge = time.Duration(cfg.CORS.MaxAge) * time.Second
	}

	return corsConfig
}

// Middleware factory functions for common use cases

// WebAppCors returns CORS middleware configured for web applications
func WebAppCors(origins []string) gin.HandlerFunc {
	config := &CorsConfig{
		AllowOrigins: origins,
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
			"X-Session-ID",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"X-Request-ID",
		},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
		OptionsResponse:  true,
	}

	middleware := NewCorsMiddlewareWithConfig(config)
	return middleware.Handler()
}

// APICors returns CORS middleware configured for API access
func APICors(origins []string) gin.HandlerFunc {
	config := &CorsConfig{
		AllowOrigins: origins,
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-API-Key",
			"X-Client-Version",
			"X-Request-ID",
			"User-Agent",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"X-Request-ID",
			"X-Rate-Limit-Remaining",
			"X-Rate-Limit-Reset",
			"X-Rate-Limit-Limit",
		},
		AllowCredentials: false, // APIs typically don't need credentials
		MaxAge:           1 * time.Hour,
		OptionsResponse:  true,
	}

	middleware := NewCorsMiddlewareWithConfig(config)
	return middleware.Handler()
}

// NoCorsCors returns a middleware that disables CORS (for same-origin only)
func NoCors() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Remove any existing CORS headers
		c.Header("Access-Control-Allow-Origin", "")
		c.Header("Access-Control-Allow-Methods", "")
		c.Header("Access-Control-Allow-Headers", "")
		c.Header("Access-Control-Allow-Credentials", "")
		c.Header("Access-Control-Max-Age", "")

		// Block preflight requests
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusMethodNotAllowed)
			return
		}

		c.Next()
	}
}
