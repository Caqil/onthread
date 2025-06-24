package utils

import (
	"fmt"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	// Common regex patterns
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	phoneRegex    = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	urlRegex      = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	hashtagRegex  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

	// Validate instance
	validate *validator.Validate
)

// Initialize validator with custom validation rules
func init() {
	validate = validator.New()

	// Register custom validators
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("objectid", validateObjectID)
	validate.RegisterValidation("phone", validatePhone)
	validate.RegisterValidation("url_optional", validateOptionalURL)
	validate.RegisterValidation("hashtag", validateHashtag)
	validate.RegisterValidation("mention", validateMention)
	validate.RegisterValidation("thread_type", validateThreadType)
	validate.RegisterValidation("visibility", validateVisibility)
	validate.RegisterValidation("reply_settings", validateReplySettings)
	validate.RegisterValidation("notification_type", validateNotificationType)
	validate.RegisterValidation("message_type", validateMessageType)
	validate.RegisterValidation("admin_role", validateAdminRole)
	validate.RegisterValidation("strong_password", validateStrongPassword)
	validate.RegisterValidation("media_type", validateMediaType)
	validate.RegisterValidation("language_code", validateLanguageCode)
}

// ValidateStruct validates a struct using the validator
func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}

// GetValidationErrors returns formatted validation errors
func GetValidationErrors(err error) map[string]string {
	errors := make(map[string]string)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			field := strings.ToLower(e.Field())
			tag := e.Tag()
			param := e.Param()

			switch tag {
			case "required":
				errors[field] = fmt.Sprintf("%s is required", field)
			case "email":
				errors[field] = "Must be a valid email address"
			case "min":
				errors[field] = fmt.Sprintf("%s must be at least %s characters", field, param)
			case "max":
				errors[field] = fmt.Sprintf("%s must not exceed %s characters", field, param)
			case "username":
				errors[field] = "Username can only contain letters, numbers, and underscores"
			case "objectid":
				errors[field] = "Must be a valid ID"
			case "phone":
				errors[field] = "Must be a valid phone number"
			case "url_optional":
				errors[field] = "Must be a valid URL"
			case "hashtag":
				errors[field] = "Hashtag can only contain letters, numbers, and underscores"
			case "strong_password":
				errors[field] = "Password must contain at least 8 characters, including uppercase, lowercase, number, and special character"
			case "thread_type":
				errors[field] = "Thread type must be one of: thread, reply, repost, quote"
			case "visibility":
				errors[field] = "Visibility must be one of: public, followers, mentioned, circle"
			case "reply_settings":
				errors[field] = "Reply settings must be one of: everyone, following, mentioned, none"
			case "notification_type":
				errors[field] = "Invalid notification type"
			case "message_type":
				errors[field] = "Message type must be one of: text, media, thread_share, system, deleted"
			case "admin_role":
				errors[field] = "Admin role must be one of: super_admin, admin, moderator, support"
			case "media_type":
				errors[field] = "Media type must be one of: image, video, gif, audio"
			case "language_code":
				errors[field] = "Must be a valid language code (e.g., en, es, fr)"
			default:
				errors[field] = fmt.Sprintf("%s is invalid", field)
			}
		}
	}

	return errors
}

// Custom validation functions
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	return usernameRegex.MatchString(username)
}

func validateObjectID(fl validator.FieldLevel) bool {
	id := fl.Field().String()
	_, err := primitive.ObjectIDFromHex(id)
	return err == nil
}

func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	if phone == "" {
		return true // Optional field
	}
	return phoneRegex.MatchString(phone)
}

func validateOptionalURL(fl validator.FieldLevel) bool {
	url := fl.Field().String()
	if url == "" {
		return true // Optional field
	}
	return urlRegex.MatchString(url)
}

func validateHashtag(fl validator.FieldLevel) bool {
	hashtag := fl.Field().String()
	return hashtagRegex.MatchString(hashtag)
}

func validateMention(fl validator.FieldLevel) bool {
	mention := fl.Field().String()
	return usernameRegex.MatchString(mention)
}

func validateThreadType(fl validator.FieldLevel) bool {
	threadType := fl.Field().String()
	validTypes := []string{"thread", "reply", "repost", "quote"}
	return contains(validTypes, threadType)
}

func validateVisibility(fl validator.FieldLevel) bool {
	visibility := fl.Field().String()
	validVisibilities := []string{"public", "followers", "mentioned", "circle"}
	return contains(validVisibilities, visibility)
}

func validateReplySettings(fl validator.FieldLevel) bool {
	settings := fl.Field().String()
	validSettings := []string{"everyone", "following", "mentioned", "none"}
	return contains(validSettings, settings)
}

func validateNotificationType(fl validator.FieldLevel) bool {
	notifType := fl.Field().String()
	validTypes := []string{"like", "reply", "repost", "quote", "follow", "mention", "dm", "thread_scheduled"}
	return contains(validTypes, notifType)
}

func validateMessageType(fl validator.FieldLevel) bool {
	msgType := fl.Field().String()
	validTypes := []string{"text", "media", "thread_share", "system", "deleted"}
	return contains(validTypes, msgType)
}

func validateAdminRole(fl validator.FieldLevel) bool {
	role := fl.Field().String()
	validRoles := []string{"super_admin", "admin", "moderator", "support"}
	return contains(validRoles, role)
}

func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	return IsValidPassword(password) == nil
}

func validateMediaType(fl validator.FieldLevel) bool {
	mediaType := fl.Field().String()
	validTypes := []string{"image", "video", "gif", "audio"}
	return contains(validTypes, mediaType)
}

func validateLanguageCode(fl validator.FieldLevel) bool {
	langCode := fl.Field().String()
	if langCode == "" {
		return true // Optional field
	}
	// Basic language code validation (ISO 639-1)
	return len(langCode) == 2 && isAlpha(langCode)
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isAlpha(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// ValidateObjectID validates MongoDB ObjectID
func ValidateObjectID(id string) error {
	if id == "" {
		return fmt.Errorf("ID is required")
	}

	if !primitive.IsValidObjectID(id) {
		return fmt.Errorf("invalid ID format")
	}

	return nil
}

// SanitizeInput sanitizes user input by removing potentially harmful characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// SanitizeHTML removes HTML tags from input (basic implementation)
func SanitizeHTML(input string) string {
	// This is a basic implementation. For production, consider using a proper HTML sanitizer
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	return htmlTagRegex.ReplaceAllString(input, "")
}

// ValidateContentLength validates content length based on type
func ValidateContentLength(content, contentType string) error {
	maxLengths := map[string]int{
		"thread":      500,
		"reply":       500,
		"bio":         500,
		"message":     2000,
		"comment":     300,
		"description": 200,
	}

	maxLength, exists := maxLengths[contentType]
	if !exists {
		maxLength = 500 // default
	}

	if len(content) > maxLength {
		return fmt.Errorf("%s must not exceed %d characters", contentType, maxLength)
	}

	return nil
}

// ValidateFileExtension validates file extensions for uploads
func ValidateFileExtension(filename string, allowedExtensions []string) error {
	if filename == "" {
		return fmt.Errorf("filename is required")
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return fmt.Errorf("file must have an extension")
	}

	// Remove the dot from extension
	ext = ext[1:]

	for _, allowed := range allowedExtensions {
		if ext == strings.ToLower(allowed) {
			return nil
		}
	}

	return fmt.Errorf("file extension .%s is not allowed", ext)
}

// GetImageExtensions returns allowed image extensions
func GetImageExtensions() []string {
	return []string{"jpg", "jpeg", "png", "gif", "webp", "svg"}
}

// GetVideoExtensions returns allowed video extensions
func GetVideoExtensions() []string {
	return []string{"mp4", "mov", "avi", "mkv", "webm", "m4v"}
}

// GetAudioExtensions returns allowed audio extensions
func GetAudioExtensions() []string {
	return []string{"mp3", "wav", "ogg", "m4a", "aac", "flac"}
}
