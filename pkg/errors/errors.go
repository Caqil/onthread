package errors

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ErrorType represents the type of error
type ErrorType string

const (
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeDatabase       ErrorType = "database"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeConflict       ErrorType = "conflict"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeStorage        ErrorType = "storage"
	ErrorTypeExternal       ErrorType = "external"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeNetwork        ErrorType = "network"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeCanceled       ErrorType = "canceled"
)

// AppError represents a custom application error
type AppError struct {
	Type       ErrorType              `json:"type"`
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	StatusCode int                    `json:"status_code"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
	UserID     string                 `json:"user_id,omitempty"`
	StackTrace string                 `json:"stack_trace,omitempty"`
	Retryable  bool                   `json:"retryable"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target
func (e *AppError) Is(target error) bool {
	if target == nil {
		return false
	}

	if appErr, ok := target.(*AppError); ok {
		return e.Type == appErr.Type && e.Code == appErr.Code
	}

	return errors.Is(e.Cause, target)
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithCause adds a cause to the error
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// WithRequestID adds a request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds a user ID to the error
func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

// WithStackTrace adds stack trace to the error
func (e *AppError) WithStackTrace() *AppError {
	if e.StackTrace == "" {
		e.StackTrace = getStackTrace()
	}
	return e
}

// NewAppError creates a new application error
func NewAppError(errorType ErrorType, code, message string, statusCode int) *AppError {
	return &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Timestamp:  time.Now(),
		Retryable:  isRetryableError(errorType),
	}
}

// Validation errors
func NewValidationError(message string, details map[string]interface{}) *AppError {
	return NewAppError(ErrorTypeValidation, "VALIDATION_ERROR", message, http.StatusBadRequest).
		WithDetails(details)
}

func NewRequiredFieldError(field string) *AppError {
	return NewValidationError(
		fmt.Sprintf("%s is required", field),
		map[string]interface{}{"field": field},
	)
}

func NewInvalidFieldError(field, value string) *AppError {
	return NewValidationError(
		fmt.Sprintf("Invalid value for %s: %s", field, value),
		map[string]interface{}{"field": field, "value": value},
	)
}

// Authentication errors
func NewAuthenticationError(message string) *AppError {
	return NewAppError(ErrorTypeAuthentication, "AUTHENTICATION_ERROR", message, http.StatusUnauthorized)
}

func NewInvalidCredentialsError() *AppError {
	return NewAuthenticationError("Invalid credentials")
}

func NewTokenExpiredError() *AppError {
	return NewAuthenticationError("Token has expired")
}

func NewInvalidTokenError() *AppError {
	return NewAuthenticationError("Invalid token")
}

// Authorization errors
func NewAuthorizationError(message string) *AppError {
	return NewAppError(ErrorTypeAuthorization, "AUTHORIZATION_ERROR", message, http.StatusForbidden)
}

func NewInsufficientPermissionsError() *AppError {
	return NewAuthorizationError("Insufficient permissions")
}

func NewAccountSuspendedError() *AppError {
	return NewAuthorizationError("Account has been suspended")
}

func NewAccountBlockedError() *AppError {
	return NewAuthorizationError("Account access has been blocked")
}

// Not found errors
func NewNotFoundError(resource string) *AppError {
	return NewAppError(ErrorTypeNotFound, "NOT_FOUND", fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

func NewUserNotFoundError() *AppError {
	return NewNotFoundError("User")
}

func NewThreadNotFoundError() *AppError {
	return NewNotFoundError("Thread")
}

func NewConversationNotFoundError() *AppError {
	return NewNotFoundError("Conversation")
}

// Conflict errors
func NewConflictError(message string) *AppError {
	return NewAppError(ErrorTypeConflict, "CONFLICT", message, http.StatusConflict)
}

func NewUserAlreadyExistsError() *AppError {
	return NewConflictError("User already exists")
}

func NewEmailAlreadyExistsError() *AppError {
	return NewConflictError("Email already registered")
}

func NewUsernameAlreadyExistsError() *AppError {
	return NewConflictError("Username already taken")
}

func NewAlreadyFollowingError() *AppError {
	return NewConflictError("Already following this user")
}

func NewAlreadyLikedError() *AppError {
	return NewConflictError("Already liked this thread")
}

// Rate limit errors
func NewRateLimitError(message string) *AppError {
	return NewAppError(ErrorTypeRateLimit, "RATE_LIMIT_EXCEEDED", message, http.StatusTooManyRequests)
}

func NewTooManyRequestsError() *AppError {
	return NewRateLimitError("Too many requests, please try again later")
}

func NewTooManyLoginAttemptsError() *AppError {
	return NewRateLimitError("Too many login attempts, please try again later")
}

// Database errors
func NewDatabaseError(message string, cause error) *AppError {
	return NewAppError(ErrorTypeDatabase, "DATABASE_ERROR", message, http.StatusInternalServerError).
		WithCause(cause).
		WithStackTrace()
}

func NewDatabaseConnectionError(cause error) *AppError {
	return NewDatabaseError("Database connection failed", cause)
}

func NewDatabaseQueryError(cause error) *AppError {
	return NewDatabaseError("Database query failed", cause)
}

// Storage errors
func NewStorageError(message string, cause error) *AppError {
	return NewAppError(ErrorTypeStorage, "STORAGE_ERROR", message, http.StatusInternalServerError).
		WithCause(cause)
}

func NewFileUploadError(cause error) *AppError {
	return NewStorageError("File upload failed", cause)
}

func NewFileNotFoundError() *AppError {
	return NewAppError(ErrorTypeStorage, "FILE_NOT_FOUND", "File not found", http.StatusNotFound)
}

func NewFileTooLargeError(maxSize int64) *AppError {
	return NewAppError(ErrorTypeValidation, "FILE_TOO_LARGE",
		fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", maxSize),
		http.StatusBadRequest).
		WithDetails(map[string]interface{}{"max_size": maxSize})
}

func NewUnsupportedFileTypeError(fileType string) *AppError {
	return NewAppError(ErrorTypeValidation, "UNSUPPORTED_FILE_TYPE",
		fmt.Sprintf("File type %s is not supported", fileType),
		http.StatusBadRequest).
		WithDetails(map[string]interface{}{"file_type": fileType})
}

// External service errors
func NewExternalServiceError(service, message string, cause error) *AppError {
	return NewAppError(ErrorTypeExternal, "EXTERNAL_SERVICE_ERROR",
		fmt.Sprintf("%s service error: %s", service, message),
		http.StatusBadGateway).
		WithCause(cause).
		WithDetails(map[string]interface{}{"service": service})
}

func NewEmailServiceError(cause error) *AppError {
	return NewExternalServiceError("Email", "Failed to send email", cause)
}

func NewPushNotificationError(cause error) *AppError {
	return NewExternalServiceError("Push Notification", "Failed to send push notification", cause)
}

// Network errors
func NewNetworkError(message string, cause error) *AppError {
	return NewAppError(ErrorTypeNetwork, "NETWORK_ERROR", message, http.StatusBadGateway).
		WithCause(cause)
}

func NewTimeoutError(operation string) *AppError {
	return NewAppError(ErrorTypeTimeout, "TIMEOUT_ERROR",
		fmt.Sprintf("Operation timed out: %s", operation),
		http.StatusRequestTimeout).
		WithDetails(map[string]interface{}{"operation": operation})
}

// Internal errors
func NewInternalError(message string, cause error) *AppError {
	return NewAppError(ErrorTypeInternal, "INTERNAL_ERROR", message, http.StatusInternalServerError).
		WithCause(cause).
		WithStackTrace()
}

func NewUnexpectedError(cause error) *AppError {
	return NewInternalError("An unexpected error occurred", cause)
}

// Content errors
func NewContentTooLongError(contentType string, maxLength int) *AppError {
	return NewValidationError(
		fmt.Sprintf("%s content exceeds maximum length of %d characters", contentType, maxLength),
		map[string]interface{}{
			"content_type": contentType,
			"max_length":   maxLength,
		},
	)
}

func NewInappropriateContentError() *AppError {
	return NewAppError(ErrorTypeValidation, "INAPPROPRIATE_CONTENT",
		"Content violates community guidelines",
		http.StatusBadRequest)
}

func NewSpamDetectedError() *AppError {
	return NewAppError(ErrorTypeValidation, "SPAM_DETECTED",
		"Content appears to be spam",
		http.StatusBadRequest)
}

// Business logic errors
func NewBusinessLogicError(message string) *AppError {
	return NewAppError(ErrorTypeValidation, "BUSINESS_LOGIC_ERROR", message, http.StatusBadRequest)
}

func NewCannotFollowSelfError() *AppError {
	return NewBusinessLogicError("Cannot follow yourself")
}

func NewCannotBlockSelfError() *AppError {
	return NewBusinessLogicError("Cannot block yourself")
}

func NewCannotReplyToDeletedThreadError() *AppError {
	return NewBusinessLogicError("Cannot reply to deleted thread")
}

func NewThreadAlreadyDeletedError() *AppError {
	return NewBusinessLogicError("Thread has already been deleted")
}

func NewConversationAlreadyExistsError() *AppError {
	return NewConflictError("Conversation already exists")
}

// Helper functions
func isRetryableError(errorType ErrorType) bool {
	retryableTypes := map[ErrorType]bool{
		ErrorTypeNetwork:  true,
		ErrorTypeTimeout:  true,
		ErrorTypeExternal: true,
		ErrorTypeDatabase: true,
		ErrorTypeStorage:  true,
	}
	return retryableTypes[errorType]
}

func getStackTrace() string {
	buf := make([]byte, 1024*4)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// WrapError wraps an existing error into an AppError
func WrapError(err error, errorType ErrorType, code, message string, statusCode int) *AppError {
	if err == nil {
		return nil
	}

	// If it's already an AppError, return it
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}

	return NewAppError(errorType, code, message, statusCode).WithCause(err)
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// GetStatusCode returns the HTTP status code for an error
func GetStatusCode(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.StatusCode
	}
	return http.StatusInternalServerError
}

// GetErrorCode returns the error code for an error
func GetErrorCode(err error) string {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code
	}
	return "UNKNOWN_ERROR"
}
