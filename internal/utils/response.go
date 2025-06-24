package utils

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id,omitempty"`
}
type Pagination struct {
	Page        int   `json:"page"`
	Limit       int   `json:"limit"`
	Total       int64 `json:"total"`
	TotalPages  int   `json:"total_pages"`
	HasNext     bool  `json:"has_next"`
	HasPrevious bool  `json:"has_previous"`
}
type APIError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
	Type    string            `json:"type,omitempty"`
}

type Meta struct {
	Pagination *PaginationMeta `json:"pagination,omitempty"`
	Sorting    *SortingMeta    `json:"sorting,omitempty"`
	Filtering  *FilteringMeta  `json:"filtering,omitempty"`
	Total      int64           `json:"total,omitempty"`
	Count      int64           `json:"count,omitempty"`
}

type PaginationMeta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
	TotalItems int64 `json:"total_items"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
	NextPage   *int  `json:"next_page,omitempty"`
	PrevPage   *int  `json:"prev_page,omitempty"`
}

type SortingMeta struct {
	Field string `json:"field"`
	Order string `json:"order"` // "asc" or "desc"
}

type FilteringMeta struct {
	Applied   map[string]interface{} `json:"applied,omitempty"`
	Available []FilterOption         `json:"available,omitempty"`
}

type FilterOption struct {
	Field       string        `json:"field"`
	Type        string        `json:"type"` // "string", "number", "boolean", "date", "enum"
	Values      []interface{} `json:"values,omitempty"`
	Description string        `json:"description"`
}

// Success responses
func SuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: time.Now(),
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

func SuccessResponseWithMeta(c *gin.Context, statusCode int, message string, data interface{}, meta *Meta) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Meta:      meta,
		Timestamp: time.Now(),
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

// Error responses
func ErrorResponse(c *gin.Context, statusCode int, code, message string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Type:    GetErrorType(statusCode),
		},
		Timestamp: time.Now(),
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

func ErrorResponseWithDetails(c *gin.Context, statusCode int, code, message string, details map[string]string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
			Type:    GetErrorType(statusCode),
		},
		Timestamp: time.Now(),
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

// Validation error response
func ValidationErrorResponse(c *gin.Context, errors map[string]string) {
	ErrorResponseWithDetails(c, http.StatusBadRequest, "VALIDATION_ERROR", "Validation failed", errors)
}

// Common error responses
func BadRequest(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusBadRequest, "BAD_REQUEST", message)
}

func Unauthorized(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", message)
}

func Forbidden(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", message)
}

func NotFound(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusNotFound, "NOT_FOUND", message)
}

func Conflict(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusConflict, "CONFLICT", message)
}

func TooManyRequests(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", message)
}

func InternalServerError(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", message)
}

func ServiceUnavailable(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message)
}

// Helper functions
func GetRequestID(c *gin.Context) string {
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}
	return primitive.NewObjectID().Hex()
}

func GetErrorType(statusCode int) string {
	switch {
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown"
	}
}
