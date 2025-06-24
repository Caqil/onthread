package routes

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"

	"onthread/internal/config"
	"onthread/internal/handlers"
	"onthread/internal/middleware"
	"onthread/internal/repository"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/internal/websocket"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// Dependencies represents all the dependencies needed for routes
type Dependencies struct {
	Config   *config.Config
	Database *mongo.Database
	Redis    *redis.Client

	// Repositories
	UserRepo         repository.UserRepository
	ThreadRepo       repository.ThreadRepository
	InteractionRepo  repository.InteractionRepository
	NotificationRepo repository.NotificationRepository
	MessageRepo      repository.MessageRepository
	AdminRepo        repository.AdminRepository

	// Services
	AuthService         services.AuthService
	UserService         services.UserService
	ThreadService       services.ThreadService
	NotificationService services.NotificationService
	MessageService      services.MessageService
	StorageService      services.StorageService
	AnalyticsService    services.AnalyticsService
	WebSocketService    services.WebSocketService

	// Handlers
	AuthHandler         *handlers.AuthHandler
	UserHandler         *handlers.UserHandler
	ThreadHandler       *handlers.ThreadHandler
	InteractionHandler  *handlers.InteractionHandler
	MessageHandler      *handlers.MessageHandler
	NotificationHandler *handlers.NotificationHandler
	AdminHandler        *handlers.AdminHandler
	UploadHandler       *handlers.UploadHandler
	WebSocketHandler    *handlers.WebSocketHandler

	// Middleware
	AuthMiddleware      *middleware.AuthMiddleware
	AdminMiddleware     *middleware.AdminMiddleware
	RateLimitMiddleware *middleware.RateLimitMiddleware
	LoggingMiddleware   *middleware.LoggingMiddleware
	CorsMiddleware      *middleware.CorsMiddleware

	// WebSocket Hub
	WebSocketHub *websocket.Hub

	// JWT Manager
	JWTManager *utils.JWTManager
}

// SetupRoutes sets up all routes and returns the configured router
func SetupRoutes(cfg *config.Config, db *mongo.Database, redis *redis.Client) *gin.Engine {
	// Initialize dependencies
	deps := initializeDependencies(cfg, db, redis)

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)

	// Create router
	router := gin.New()

	// Setup middleware
	setupMiddleware(router, deps)

	// Setup routes
	setupAPIRoutes(router, deps)

	// Setup WebSocket routes
	setupWebSocketRoutes(router, deps)

	// Setup health check
	setupHealthCheck(router, deps)

	return router
}

// initializeDependencies initializes all dependencies
func initializeDependencies(cfg *config.Config, db *mongo.Database, redis *redis.Client) *Dependencies {
	// Initialize JWT Manager
	jwtManager := utils.NewJWTManager(
		cfg.JWT.Secret,
		cfg.Admin.JWTSecret,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	threadRepo := repository.NewThreadRepository(db)
	interactionRepo := repository.NewInteractionRepository(db)
	notificationRepo := repository.NewNotificationRepository(db)
	messageRepo := repository.NewMessageRepository(db)
	adminRepo := repository.NewAdminRepository(db)

	// Initialize services
	authService := services.NewAuthService(userRepo, jwtManager, redis)
	userService := services.NewUserService(userRepo, redis)
	threadService := services.NewThreadService(threadRepo, userRepo, interactionRepo, redis)
	notificationService := services.NewNotificationService(notificationRepo, userRepo, redis)
	messageService := services.NewMessageService(messageRepo, userRepo, redis)

	// Initialize storage service
	storageClient, err := config.NewStorageClient(cfg)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize storage client")
	}
	storageService := services.NewStorageService(storageClient)

	analyticsService := services.NewAnalyticsService(db, redis)

	// Initialize WebSocket hub
	wsHub := websocket.NewHub(redis, userRepo, interactionRepo, websocket.DefaultHubConfig())
	wsHub.Start()
	wsService := services.NewWebSocketService(wsHub, notificationService)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, jwtManager)
	userHandler := handlers.NewUserHandler(userService, authService)
	threadHandler := handlers.NewThreadHandler(threadService, userService)
	interactionHandler := handlers.NewInteractionHandler(interactionRepo, threadService, userService, notificationService)
	messageHandler := handlers.NewMessageHandler(messageService, wsService)
	notificationHandler := handlers.NewNotificationHandler(notificationService)
	adminHandler := handlers.NewAdminHandler(adminRepo, userRepo, threadRepo, analyticsService)
	uploadHandler := handlers.NewUploadHandler(storageService)
	wsHandler := handlers.NewWebSocketHandler(wsHub, authService)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, userRepo)
	adminMiddleware := middleware.NewAdminMiddleware(jwtManager, adminRepo)
	rateLimitMiddleware := middleware.NewRateLimitMiddleware(redis)
	loggingMiddleware := middleware.NewLoggingMiddleware()
	corsMiddleware := middleware.NewCorsMiddleware()

	return &Dependencies{
		Config:              cfg,
		Database:            db,
		Redis:               redis,
		UserRepo:            userRepo,
		ThreadRepo:          threadRepo,
		InteractionRepo:     interactionRepo,
		NotificationRepo:    notificationRepo,
		MessageRepo:         messageRepo,
		AdminRepo:           adminRepo,
		AuthService:         authService,
		UserService:         userService,
		ThreadService:       threadService,
		NotificationService: notificationService,
		MessageService:      messageService,
		StorageService:      storageService,
		AnalyticsService:    analyticsService,
		WebSocketService:    wsService,
		AuthHandler:         authHandler,
		UserHandler:         userHandler,
		ThreadHandler:       threadHandler,
		InteractionHandler:  interactionHandler,
		MessageHandler:      messageHandler,
		NotificationHandler: notificationHandler,
		AdminHandler:        adminHandler,
		UploadHandler:       uploadHandler,
		WebSocketHandler:    wsHandler,
		AuthMiddleware:      authMiddleware,
		AdminMiddleware:     adminMiddleware,
		RateLimitMiddleware: rateLimitMiddleware,
		LoggingMiddleware:   loggingMiddleware,
		CorsMiddleware:      corsMiddleware,
		WebSocketHub:        wsHub,
		JWTManager:          jwtManager,
	}
}

// setupMiddleware sets up global middleware
func setupMiddleware(router *gin.Engine, deps *Dependencies) {
	// Recovery middleware
	router.Use(gin.Recovery())

	// Logging middleware
	router.Use(deps.LoggingMiddleware.LogRequests())

	// CORS middleware
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Configure based on your needs
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Request ID middleware
	router.Use(deps.LoggingMiddleware.RequestID())

	// Security headers middleware
	router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	})
}

// setupAPIRoutes sets up all API routes
func setupAPIRoutes(router *gin.Engine, deps *Dependencies) {
	// API v1 group
	api := router.Group("/api/v1")

	// Setup route groups
	setupAuthRoutes(api, deps)
	setupUserRoutes(api, deps)
	setupThreadRoutes(api, deps)
	setupMessageRoutes(api, deps)
	setupNotificationRoutes(api, deps)
	setupUploadRoutes(api, deps)
	setupAdminRoutes(api, deps)
}

// setupWebSocketRoutes sets up WebSocket routes
func setupWebSocketRoutes(router *gin.Engine, deps *Dependencies) {
	wsGroup := router.Group("/ws")
	setupWebSocketHandlers(wsGroup, deps)
}

// setupHealthCheck sets up health check endpoint
func setupHealthCheck(router *gin.Engine, deps *Dependencies) {
	router.GET("/health", func(c *gin.Context) {
		// Check database connection
		if err := deps.Database.Client().Ping(c.Request.Context(), nil); err != nil {
			utils.ServiceUnavailable(c, "Database connection failed")
			return
		}

		// Check Redis connection
		if err := deps.Redis.Ping(c.Request.Context()).Err(); err != nil {
			utils.ServiceUnavailable(c, "Redis connection failed")
			return
		}

		utils.SuccessResponse(c, http.StatusOK, "Service is healthy", gin.H{
			"timestamp": time.Now(),
			"version":   constants.AppVersion,
			"status":    "healthy",
			"services": gin.H{
				"database":  "healthy",
				"redis":     "healthy",
				"websocket": "healthy",
			},
		})
	})

	// Detailed health check for admin
	router.GET("/health/detailed", deps.AdminMiddleware.RequireAdmin(), func(c *gin.Context) {
		stats := deps.WebSocketHub.GetStats()

		utils.SuccessResponse(c, http.StatusOK, "Detailed health information", gin.H{
			"timestamp": time.Now(),
			"version":   constants.AppVersion,
			"uptime":    time.Since(time.Now()).String(), // You'd track actual uptime
			"websocket": stats,
			"system": gin.H{
				"goroutines": "tracked_separately",
				"memory":     "tracked_separately",
			},
		})
	})
}
