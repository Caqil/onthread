package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// RateLimitMiddleware handles rate limiting using Redis
type RateLimitMiddleware struct {
	redis  *redis.Client
	config *RateLimitConfig
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	GlobalEnabled  bool
	PerUserEnabled bool
	PerIPEnabled   bool
	SkipSuccessful bool
	SkipPaths      []string
	TrustedProxies []string
	HeaderPrefix   string
	ErrorMessage   string
	KeyGenerator   func(*gin.Context, string) string
}

// RateLimiter represents a specific rate limiter
type RateLimiter struct {
	redis      *redis.Client
	limit      int
	window     time.Duration
	identifier string
	keyPrefix  string
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(redis *redis.Client) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		redis:  redis,
		config: DefaultRateLimitConfig(),
	}
}

// NewRateLimitMiddlewareWithConfig creates a new rate limiting middleware with custom config
func NewRateLimitMiddlewareWithConfig(redis *redis.Client, config *RateLimitConfig) *RateLimitMiddleware {
	if config == nil {
		config = DefaultRateLimitConfig()
	}
	return &RateLimitMiddleware{
		redis:  redis,
		config: config,
	}
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		GlobalEnabled:  true,
		PerUserEnabled: true,
		PerIPEnabled:   true,
		SkipSuccessful: false,
		SkipPaths: []string{
			"/health",
			"/ping",
			"/metrics",
		},
		TrustedProxies: []string{},
		HeaderPrefix:   "X-Rate-Limit",
		ErrorMessage:   "Rate limit exceeded. Please try again later.",
		KeyGenerator:   defaultKeyGenerator,
	}
}

// CreateRateLimiter creates a specific rate limiter
func (m *RateLimitMiddleware) CreateRateLimiter(limit int, identifier string) gin.HandlerFunc {
	limiter := &RateLimiter{
		redis:      m.redis,
		limit:      limit,
		window:     time.Minute, // Default to per minute
		identifier: identifier,
		keyPrefix:  "rate_limit",
	}

	return limiter.Handler()
}

// CreateRateLimiterWithWindow creates a rate limiter with custom time window
func (m *RateLimitMiddleware) CreateRateLimiterWithWindow(limit int, window time.Duration, identifier string) gin.HandlerFunc {
	limiter := &RateLimiter{
		redis:      m.redis,
		limit:      limit,
		window:     window,
		identifier: identifier,
		keyPrefix:  "rate_limit",
	}

	return limiter.Handler()
}

// Handler returns the rate limiter middleware handler
func (rl *RateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for certain paths
		if rl.shouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Generate rate limit key
		key := rl.generateKey(c)

		// Check rate limit
		allowed, remaining, resetTime, err := rl.checkRateLimit(c.Request.Context(), key)
		if err != nil {
			logger.WithContext(c.Request.Context()).WithError(err).Error("Rate limit check failed")
			c.Next() // Continue on Redis error
			return
		}

		// Set rate limit headers
		rl.setRateLimitHeaders(c, remaining, resetTime)

		if !allowed {
			// Log rate limit exceeded
			logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
				"key":        key,
				"limit":      rl.limit,
				"window":     rl.window.String(),
				"identifier": rl.identifier,
				"client_ip":  c.ClientIP(),
				"user_agent": c.GetHeader("User-Agent"),
			}).Warn("Rate limit exceeded")

			utils.TooManyRequests(c, "Rate limit exceeded. Please try again later.")
			c.Abort()
			return
		}

		c.Next()
	}
}

// checkRateLimit implements sliding window rate limiting using Redis
func (rl *RateLimiter) checkRateLimit(ctx context.Context, key string) (bool, int, time.Time, error) {
	now := time.Now()
	windowStart := now.Add(-rl.window)

	pipe := rl.redis.Pipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart.UnixNano(), 10))

	// Count current requests
	pipe.ZCard(ctx, key)

	// Add current request
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Set expiration
	pipe.Expire(ctx, key, rl.window+time.Second)

	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	// Get current count
	countCmd := cmders[1].(*redis.IntCmd)
	count, err := countCmd.Result()
	if err != nil {
		return false, 0, time.Time{}, err
	}

	remaining := rl.limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	resetTime := now.Add(rl.window)
	allowed := count < int64(rl.limit)

	return allowed, remaining, resetTime, nil
}

// generateKey generates a unique key for rate limiting
func (rl *RateLimiter) generateKey(c *gin.Context) string {
	var identifier string

	// Try to get user ID first
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(primitive.ObjectID); ok {
			identifier = fmt.Sprintf("user:%s", id.Hex())
		}
	}

	// Fall back to IP address
	if identifier == "" {
		identifier = fmt.Sprintf("ip:%s", c.ClientIP())
	}

	return fmt.Sprintf("%s:%s:%s", rl.keyPrefix, rl.identifier, identifier)
}

// setRateLimitHeaders sets rate limiting headers
func (rl *RateLimiter) setRateLimitHeaders(c *gin.Context, remaining int, resetTime time.Time) {
	c.Header("X-Rate-Limit-Limit", strconv.Itoa(rl.limit))
	c.Header("X-Rate-Limit-Remaining", strconv.Itoa(remaining))
	c.Header("X-Rate-Limit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
	c.Header("X-Rate-Limit-Window", rl.window.String())
}

// shouldSkip determines if rate limiting should be skipped
func (rl *RateLimiter) shouldSkip(path string) bool {
	skipPaths := []string{
		"/health",
		"/ping",
		"/metrics",
		"/favicon.ico",
	}

	for _, skipPath := range skipPaths {
		if path == skipPath {
			return true
		}
	}

	return false
}

// Predefined rate limiters for common use cases

// GlobalRateLimit applies a global rate limit
func (m *RateLimitMiddleware) GlobalRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.GeneralAPIRateLimit, "global")
}

// AuthRateLimit applies rate limiting for authentication endpoints
func (m *RateLimitMiddleware) AuthRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.LoginRateLimit, "auth")
}

// APIRateLimit applies rate limiting for general API endpoints
func (m *RateLimitMiddleware) APIRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.GeneralAPIRateLimit, "api")
}

// UploadRateLimit applies rate limiting for upload endpoints
func (m *RateLimitMiddleware) UploadRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.UploadRateLimit, "upload")
}

// SearchRateLimit applies rate limiting for search endpoints
func (m *RateLimitMiddleware) SearchRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.SearchRateLimit, "search")
}

// AdminRateLimit applies rate limiting for admin endpoints
func (m *RateLimitMiddleware) AdminRateLimit() gin.HandlerFunc {
	return m.CreateRateLimiter(constants.AdminAPIRateLimit, "admin")
}

// Custom rate limiters

// PerUserRateLimit creates a rate limiter that limits per user
func (m *RateLimitMiddleware) PerUserRateLimit(limit int, window time.Duration, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.Next()
			return
		}

		key := fmt.Sprintf("rate_limit:user:%s:%s", userID.(primitive.ObjectID).Hex(), action)
		allowed, remaining, resetTime, err := m.checkSlidingWindow(c.Request.Context(), key, limit, window)

		if err != nil {
			logger.WithContext(c.Request.Context()).WithError(err).Error("User rate limit check failed")
			c.Next()
			return
		}

		m.setHeaders(c, limit, remaining, resetTime)

		if !allowed {
			utils.TooManyRequests(c, fmt.Sprintf("Rate limit exceeded for %s. Please try again later.", action))
			c.Abort()
			return
		}

		c.Next()
	}
}

// PerIPRateLimit creates a rate limiter that limits per IP address
func (m *RateLimitMiddleware) PerIPRateLimit(limit int, window time.Duration, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := fmt.Sprintf("rate_limit:ip:%s:%s", c.ClientIP(), action)
		allowed, remaining, resetTime, err := m.checkSlidingWindow(c.Request.Context(), key, limit, window)

		if err != nil {
			logger.WithContext(c.Request.Context()).WithError(err).Error("IP rate limit check failed")
			c.Next()
			return
		}

		m.setHeaders(c, limit, remaining, resetTime)

		if !allowed {
			logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
				"ip":     c.ClientIP(),
				"action": action,
				"limit":  limit,
				"window": window.String(),
			}).Warn("IP rate limit exceeded")

			utils.TooManyRequests(c, fmt.Sprintf("Rate limit exceeded for %s. Please try again later.", action))
			c.Abort()
			return
		}

		c.Next()
	}
}

// BurstRateLimit allows burst traffic but maintains average rate
func (m *RateLimitMiddleware) BurstRateLimit(burst int, rate int, window time.Duration, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := m.getIdentifier(c)
		key := fmt.Sprintf("rate_limit:burst:%s:%s", identifier, action)

		allowed, err := m.checkTokenBucket(c.Request.Context(), key, burst, rate, window)
		if err != nil {
			logger.WithContext(c.Request.Context()).WithError(err).Error("Burst rate limit check failed")
			c.Next()
			return
		}

		if !allowed {
			utils.TooManyRequests(c, "Rate limit exceeded. Please try again later.")
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper methods

// checkSlidingWindow implements sliding window rate limiting
func (m *RateLimitMiddleware) checkSlidingWindow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Time, error) {
	now := time.Now()
	windowStart := now.Add(-window)

	pipe := m.redis.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart.UnixNano(), 10))
	pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.UnixNano()), Member: now.UnixNano()})
	pipe.Expire(ctx, key, window+time.Second)

	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	count, err := cmders[1].(*redis.IntCmd).Result()
	if err != nil {
		return false, 0, time.Time{}, err
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	resetTime := now.Add(window)
	allowed := count < int64(limit)

	return allowed, remaining, resetTime, nil
}

// checkTokenBucket implements token bucket rate limiting
func (m *RateLimitMiddleware) checkTokenBucket(ctx context.Context, key string, burst int, rate int, window time.Duration) (bool, error) {
	script := `
		local key = KEYS[1]
		local burst = tonumber(ARGV[1])
		local rate = tonumber(ARGV[2])
		local window = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or burst
		local last_refill = tonumber(bucket[2]) or now
		
		-- Calculate tokens to add
		local elapsed = now - last_refill
		local tokens_to_add = math.floor((elapsed / window) * rate)
		tokens = math.min(burst, tokens + tokens_to_add)
		
		if tokens >= 1 then
			tokens = tokens - 1
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
			redis.call('EXPIRE', key, window * 2)
			return 1
		else
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
			redis.call('EXPIRE', key, window * 2)
			return 0
		end
	`

	result, err := m.redis.Eval(ctx, script, []string{key}, burst, rate, window.Seconds(), time.Now().Unix()).Result()
	if err != nil {
		return false, err
	}

	return result.(int64) == 1, nil
}

// getIdentifier returns the best identifier for rate limiting
func (m *RateLimitMiddleware) getIdentifier(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%s", userID.(primitive.ObjectID).Hex())
	}
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// setHeaders sets rate limit headers
func (m *RateLimitMiddleware) setHeaders(c *gin.Context, limit int, remaining int, resetTime time.Time) {
	c.Header("X-Rate-Limit-Limit", strconv.Itoa(limit))
	c.Header("X-Rate-Limit-Remaining", strconv.Itoa(remaining))
	c.Header("X-Rate-Limit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
}

// defaultKeyGenerator is the default key generation function
func defaultKeyGenerator(c *gin.Context, identifier string) string {
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("rate_limit:%s:user:%s", identifier, userID.(primitive.ObjectID).Hex())
	}
	return fmt.Sprintf("rate_limit:%s:ip:%s", identifier, c.ClientIP())
}

// Utility functions for specific use cases

// SlidingWindowLimiter creates a sliding window rate limiter
func SlidingWindowLimiter(redis *redis.Client, limit int, window time.Duration, keyPrefix string) gin.HandlerFunc {
	middleware := NewRateLimitMiddleware(redis)
	return middleware.CreateRateLimiterWithWindow(limit, window, keyPrefix)
}

// FixedWindowLimiter creates a fixed window rate limiter
func FixedWindowLimiter(redis *redis.Client, limit int, window time.Duration, keyPrefix string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := fmt.Sprintf("rate_limit:fixed:%s:%s", keyPrefix, defaultKeyGenerator(c, keyPrefix))

		// Use Redis INCR with TTL for fixed window
		pipe := redis.Pipeline()
		pipe.Incr(c.Request.Context(), key)
		pipe.Expire(c.Request.Context(), key, window)

		cmders, err := pipe.Exec(c.Request.Context())
		if err != nil {
			logger.WithContext(c.Request.Context()).WithError(err).Error("Fixed window rate limit check failed")
			c.Next()
			return
		}

		count, err := cmders[0].(*redis.IntCmd).Result()
		if err != nil {
			c.Next()
			return
		}

		if count > int64(limit) {
			utils.TooManyRequests(c, "Rate limit exceeded. Please try again later.")
			c.Abort()
			return
		}

		c.Next()
	}
}
