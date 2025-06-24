package constants

import "time"

// Application constants
const (
	AppName         = "ThreadApp"
	AppVersion      = "1.0.0"
	APIVersion      = "v1"
	DefaultLocale   = "en"
	DefaultTimezone = "UTC"
)

// Server constants
const (
	DefaultPort     = "8080"
	ReadTimeout     = 30 * time.Second
	WriteTimeout    = 30 * time.Second
	IdleTimeout     = 60 * time.Second
	MaxHeaderBytes  = 1 << 20 // 1MB
	ShutdownTimeout = 30 * time.Second
)

// Database constants
const (
	DatabaseTimeout = 10 * time.Second
	MaxPoolSize     = 100
	MinPoolSize     = 5
	MaxIdleTime     = 30 * time.Second

	// Collection names
	UsersCollection                    = "users"
	ThreadsCollection                  = "threads"
	FollowsCollection                  = "follows"
	BlocksCollection                   = "blocks"
	MutesCollection                    = "mutes"
	LikesCollection                    = "likes"
	RepostsCollection                  = "reposts"
	BookmarksCollection                = "bookmarks"
	BookmarkFoldersCollection          = "bookmark_folders"
	SharesCollection                   = "shares"
	ReportsCollection                  = "reports"
	UserListsCollection                = "user_lists"
	ListMembersCollection              = "list_members"
	ListFollowersCollection            = "list_followers"
	NotificationsCollection            = "notifications"
	NotificationGroupsCollection       = "notification_groups"
	NotificationSettingsCollection     = "notification_settings"
	EmailQueueCollection               = "email_queue"
	ConversationsCollection            = "conversations"
	MessagesCollection                 = "messages"
	ConversationParticipantsCollection = "conversation_participants"
	TypingIndicatorsCollection         = "typing_indicators"
	AdminsCollection                   = "admins"
	AdminSessionsCollection            = "admin_sessions"
	AdminLogsCollection                = "admin_logs"
	SystemConfigsCollection            = "system_configs"
	SystemStatsCollection              = "system_stats"
	ModerationActionsCollection        = "moderation_actions"
	ContentFiltersCollection           = "content_filters"
	AuditLogsCollection                = "audit_logs"
	PollVotesCollection                = "poll_votes"
	ThreadViewsCollection              = "thread_views"
	MediaFilesCollection               = "media_files"
)

// Redis keys
const (
	RedisKeyPrefix          = "thread_app:"
	UserSessionPrefix       = RedisKeyPrefix + "session:user:"
	AdminSessionPrefix      = RedisKeyPrefix + "session:admin:"
	UserCachePrefix         = RedisKeyPrefix + "cache:user:"
	ThreadCachePrefix       = RedisKeyPrefix + "cache:thread:"
	NotificationCachePrefix = RedisKeyPrefix + "cache:notification:"
	RateLimitPrefix         = RedisKeyPrefix + "rate_limit:"
	OnlineUsersKey          = RedisKeyPrefix + "online_users"
	TrendingHashtagsKey     = RedisKeyPrefix + "trending_hashtags"
	TrendingTopicsKey       = RedisKeyPrefix + "trending_topics"
	SystemStatsKey          = RedisKeyPrefix + "system_stats"
	WebSocketRoomPrefix     = RedisKeyPrefix + "ws_room:"
	TypingPrefix            = RedisKeyPrefix + "typing:"
	EmailQueueKey           = RedisKeyPrefix + "email_queue"
	PushNotificationQueue   = RedisKeyPrefix + "push_queue"
)

// Cache TTL
const (
	UserCacheTTL        = 1 * time.Hour
	ThreadCacheTTL      = 30 * time.Minute
	TrendingCacheTTL    = 15 * time.Minute
	SystemStatsCacheTTL = 5 * time.Minute
	SessionCacheTTL     = 24 * time.Hour
	OnlineUsersTTL      = 5 * time.Minute
	TypingIndicatorTTL  = 10 * time.Second
	RateLimitTTL        = 1 * time.Hour
)

// Authentication constants
const (
	JWTIssuer                 = "thread-app"
	JWTAudience               = "thread-app-users"
	JWTAdminAudience          = "thread-app-admin"
	JWTResetAudience          = "thread-app-reset"
	JWTVerifyAudience         = "thread-app-verify"
	DefaultAccessExpiry       = 1 * time.Hour
	DefaultRefreshExpiry      = 7 * 24 * time.Hour
	DefaultResetExpiry        = 1 * time.Hour
	DefaultVerifyExpiry       = 24 * time.Hour
	MaxActiveSessionsPerUser  = 5
	MaxActiveSessionsPerAdmin = 3
)

// Token types
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeAdmin   = "admin"
	TokenTypeReset   = "reset"
	TokenTypeVerify  = "verify"
)

// User constants
const (
	MinUsernameLength    = 3
	MaxUsernameLength    = 30
	MinPasswordLength    = 8
	MaxPasswordLength    = 128
	MaxDisplayNameLength = 50
	MaxBioLength         = 500
	MaxLocationLength    = 100
	MaxWebsiteLength     = 200
	MaxUserLinksCount    = 5
	DefaultFollowLimit   = 5000
	MaxFollowLimit       = 10000
)

// Thread constants
const (
	MaxThreadContentLength = 500
	MaxReplyContentLength  = 500
	MaxMediaFilesPerThread = 4
	MaxPollOptions         = 4
	MaxPollOptionLength    = 50
	MaxHashtagsPerThread   = 10
	MaxMentionsPerThread   = 20
	MaxHashtagLength       = 50
	MaxThreadsPerMinute    = 10
	MaxRepliesPerMinute    = 20
	DefaultPollDuration    = 24 * time.Hour
	MaxPollDuration        = 7 * 24 * time.Hour
	ThreadEditTimeLimit    = 5 * time.Minute
)

// Media constants
const (
	MaxImageSize     = 10 * 1024 * 1024  // 10MB
	MaxVideoSize     = 100 * 1024 * 1024 // 100MB
	MaxAudioSize     = 50 * 1024 * 1024  // 50MB
	MaxFileSize      = 100 * 1024 * 1024 // 100MB for general files
	ImageQuality     = 85
	ThumbnailWidth   = 300
	ThumbnailHeight  = 300
	PreviewWidth     = 800
	PreviewHeight    = 600
	MaxAltTextLength = 200

	// Supported formats
	SupportedImageFormats = "jpg,jpeg,png,gif,webp"
	SupportedVideoFormats = "mp4,mov,avi,mkv,webm,m4v"
	SupportedAudioFormats = "mp3,wav,ogg,m4a,aac,flac"
)

// Message constants
const (
	MaxMessageContentLength        = 2000
	MaxMessageMediaFiles           = 10
	MaxConversationParticipants    = 100
	MaxGroupNameLength             = 50
	MaxGroupDescriptionLength      = 200
	MessageEditTimeLimit           = 5 * time.Minute
	TypingIndicatorDuration        = 10 * time.Second
	MessageReadTimeout             = 30 * time.Second
	MaxMessagesPerMinute           = 30
	DisappearingMessageMinDuration = 10 * time.Second
	DisappearingMessageMaxDuration = 7 * 24 * time.Hour
)

// Notification constants
const (
	MaxNotificationsPerUser   = 1000
	NotificationBatchSize     = 50
	NotificationRetryAttempts = 3
	NotificationRetryDelay    = 5 * time.Minute
	MaxEmailQueueSize         = 10000
	EmailRetryAttempts        = 3
	EmailRetryDelay           = 15 * time.Minute
	PushNotificationTimeout   = 30 * time.Second
	NotificationGroupTimeout  = 1 * time.Hour
)

// Rate limiting constants
const (
	// Authentication rate limits
	LoginRateLimit         = 5 // per minute
	RegisterRateLimit      = 3 // per minute
	PasswordResetRateLimit = 3 // per hour
	EmailVerifyRateLimit   = 5 // per hour

	// API rate limits
	GeneralAPIRateLimit  = 100 // per minute
	ThreadPostRateLimit  = 10  // per minute
	MessageSendRateLimit = 30  // per minute
	SearchRateLimit      = 20  // per minute
	UploadRateLimit      = 10  // per minute
	FollowRateLimit      = 50  // per minute
	LikeRateLimit        = 100 // per minute

	// Admin rate limits
	AdminAPIRateLimit   = 200 // per minute
	ModerationRateLimit = 50  // per minute
)

// WebSocket constants
const (
	WebSocketReadBufferSize   = 1024
	WebSocketWriteBufferSize  = 1024
	WebSocketPingPeriod       = 54 * time.Second
	WebSocketPongWait         = 60 * time.Second
	WebSocketWriteWait        = 10 * time.Second
	MaxWebSocketConnections   = 10000
	WebSocketMessageSizeLimit = 512
)

// Content types
const (
	ContentTypeThread  = "thread"
	ContentTypeReply   = "reply"
	ContentTypeRepost  = "repost"
	ContentTypeQuote   = "quote"
	ContentTypeMessage = "message"
	ContentTypeBio     = "bio"
	ContentTypeComment = "comment"
)

// Thread types
const (
	ThreadTypeThread = "thread"
	ThreadTypeReply  = "reply"
	ThreadTypeRepost = "repost"
	ThreadTypeQuote  = "quote"
)

// Visibility types
const (
	VisibilityPublic    = "public"
	VisibilityFollowers = "followers"
	VisibilityMentioned = "mentioned"
	VisibilityCircle    = "circle"
)

// Reply settings
const (
	ReplySettingsEveryone  = "everyone"
	ReplySettingsFollowing = "following"
	ReplySettingsMentioned = "mentioned"
	ReplySettingsNone      = "none"
)

// User roles
const (
	RoleUser = "user"
)

// Admin roles
const (
	RoleSuperAdmin = "super_admin"
	RoleAdmin      = "admin"
	RoleModerator  = "moderator"
	RoleSupport    = "support"
)

// Notification types
const (
	NotificationTypeLike            = "like"
	NotificationTypeReply           = "reply"
	NotificationTypeRepost          = "repost"
	NotificationTypeQuote           = "quote"
	NotificationTypeFollow          = "follow"
	NotificationTypeMention         = "mention"
	NotificationTypeDM              = "dm"
	NotificationTypeThreadScheduled = "thread_scheduled"
)

// Message types
const (
	MessageTypeText        = "text"
	MessageTypeMedia       = "media"
	MessageTypeThreadShare = "thread_share"
	MessageTypeSystem      = "system"
	MessageTypeDeleted     = "deleted"
)

// Media types
const (
	MediaTypeImage = "image"
	MediaTypeVideo = "video"
	MediaTypeGIF   = "gif"
	MediaTypeAudio = "audio"
)

// Report types
const (
	ReportTypeSpam           = "spam"
	ReportTypeHarassment     = "harassment"
	ReportTypeHateSpeech     = "hate_speech"
	ReportTypeViolence       = "violence"
	ReportTypeSexualContent  = "sexual_content"
	ReportTypeMisinformation = "misinformation"
	ReportTypeCopyright      = "copyright"
	ReportTypeOther          = "other"
)

// Report statuses
const (
	ReportStatusPending   = "pending"
	ReportStatusReviewing = "reviewing"
	ReportStatusResolved  = "resolved"
	ReportStatusDismissed = "dismissed"
)

// Report priorities
const (
	ReportPriorityLow    = "low"
	ReportPriorityMedium = "medium"
	ReportPriorityHigh   = "high"
	ReportPriorityUrgent = "urgent"
)

// Moderation actions
const (
	ModerationActionWarn    = "warn"
	ModerationActionSuspend = "suspend"
	ModerationActionBan     = "ban"
	ModerationActionDelete  = "delete"
	ModerationActionHide    = "hide"
	ModerationActionFeature = "feature"
)

// Storage providers
const (
	StorageProviderS3     = "s3"
	StorageProviderWasabi = "wasabi"
	StorageProviderR2     = "r2"
)

// Email types
const (
	EmailTypeWelcome             = "welcome"
	EmailTypeVerification        = "verification"
	EmailTypePasswordReset       = "password_reset"
	EmailTypePasswordChanged     = "password_changed"
	EmailTypeSecurityAlert       = "security_alert"
	EmailTypeWeeklyDigest        = "weekly_digest"
	EmailTypeNotificationSummary = "notification_summary"
)

// Push notification types
const (
	PushTypeNewMessage   = "new_message"
	PushTypeNewLike      = "new_like"
	PushTypeNewFollow    = "new_follow"
	PushTypeNewReply     = "new_reply"
	PushTypeNewMention   = "new_mention"
	PushTypeThreadUpdate = "thread_update"
)

// WebSocket message types
const (
	WSTypeMessage      = "message"
	WSTypeNotification = "notification"
	WSTypeTyping       = "typing"
	WSTypeOnlineStatus = "online_status"
	WSTypeThreadUpdate = "thread_update"
	WSTypeError        = "error"
	WSTypePing         = "ping"
	WSTypePong         = "pong"
)

// System configuration categories
const (
	ConfigCategoryGeneral  = "general"
	ConfigCategorySecurity = "security"
	ConfigCategoryFeatures = "features"
	ConfigCategoryLimits   = "limits"
	ConfigCategoryStorage  = "storage"
	ConfigCategoryEmail    = "email"
	ConfigCategoryPush     = "push"
)

// Content filter types
const (
	FilterTypeKeyword = "keyword"
	FilterTypeRegex   = "regex"
	FilterTypeAIModel = "ai_model"
	FilterTypeHash    = "hash"
)

// Content filter actions
const (
	FilterActionHide   = "hide"
	FilterActionFlag   = "flag"
	FilterActionDelete = "delete"
	FilterActionWarn   = "warn"
)

// Content filter severities
const (
	FilterSeverityLow      = "low"
	FilterSeverityMedium   = "medium"
	FilterSeverityHigh     = "high"
	FilterSeverityCritical = "critical"
)

// HTTP headers
const (
	HeaderContentType    = "Content-Type"
	HeaderAuthorization  = "Authorization"
	HeaderUserAgent      = "User-Agent"
	HeaderXForwardedFor  = "X-Forwarded-For"
	HeaderXRealIP        = "X-Real-IP"
	HeaderXRequestID     = "X-Request-ID"
	HeaderAcceptLanguage = "Accept-Language"
	HeaderCacheControl   = "Cache-Control"
	HeaderETag           = "ETag"
	HeaderLastModified   = "Last-Modified"
)

// Content types for responses
const (
	ContentTypeJSON = "application/json"
	ContentTypeXML  = "application/xml"
	ContentTypeHTML = "text/html"
	ContentTypeText = "text/plain"
)

// Error codes
const (
	ErrCodeBadRequest          = "BAD_REQUEST"
	ErrCodeUnauthorized        = "UNAUTHORIZED"
	ErrCodeForbidden           = "FORBIDDEN"
	ErrCodeNotFound            = "NOT_FOUND"
	ErrCodeConflict            = "CONFLICT"
	ErrCodeValidationError     = "VALIDATION_ERROR"
	ErrCodeRateLimitExceeded   = "RATE_LIMIT_EXCEEDED"
	ErrCodeInternalServerError = "INTERNAL_SERVER_ERROR"
	ErrCodeServiceUnavailable  = "SERVICE_UNAVAILABLE"
	ErrCodeDatabaseError       = "DATABASE_ERROR"
	ErrCodeStorageError        = "STORAGE_ERROR"
	ErrCodeEmailError          = "EMAIL_ERROR"
	ErrCodeWebSocketError      = "WEBSOCKET_ERROR"
)

// Time formats
const (
	TimeFormatISO8601  = "2006-01-02T15:04:05Z07:00"
	TimeFormatDate     = "2006-01-02"
	TimeFormatTime     = "15:04:05"
	TimeFormatDateTime = "2006-01-02 15:04:05"
	TimeFormatReadable = "January 2, 2006 at 3:04 PM"
)

// Pagination defaults
const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
	MinLimit     = 1
)

// Language codes (ISO 639-1)
var SupportedLanguages = []string{
	"en", "es", "fr", "de", "it", "pt", "ru", "ja", "ko", "zh",
	"ar", "hi", "tr", "pl", "nl", "sv", "da", "no", "fi", "hu",
}

// Theme options
var SupportedThemes = []string{
	"light", "dark", "auto",
}

// Timezone list (common timezones)
var SupportedTimezones = []string{
	"UTC", "America/New_York", "America/Los_Angeles", "America/Chicago",
	"Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo",
	"Asia/Shanghai", "Asia/Kolkata", "Australia/Sydney", "America/Sao_Paulo",
}

// File upload limits by type
var FileSizeLimits = map[string]int64{
	MediaTypeImage: MaxImageSize,
	MediaTypeVideo: MaxVideoSize,
	MediaTypeAudio: MaxAudioSize,
	"document":     MaxFileSize,
}

// Allowed file extensions by type
var AllowedExtensions = map[string][]string{
	MediaTypeImage: {"jpg", "jpeg", "png", "gif", "webp", "svg"},
	MediaTypeVideo: {"mp4", "mov", "avi", "mkv", "webm", "m4v"},
	MediaTypeAudio: {"mp3", "wav", "ogg", "m4a", "aac", "flac"},
	"document":     {"pdf", "doc", "docx", "txt", "md"},
}
