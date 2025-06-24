package routes

import (
	"onthread/pkg/constants"

	"github.com/gin-gonic/gin"
)

// setupAuthRoutes sets up authentication routes
func setupAuthRoutes(api *gin.RouterGroup, deps *Dependencies) {
	auth := api.Group("/auth")

	// Rate limiting for auth endpoints
	authRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.LoginRateLimit,
		"auth",
	)

	registerRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.RegisterRateLimit,
		"register",
	)

	resetRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.PasswordResetRateLimit,
		"password_reset",
	)

	// Public auth routes
	auth.POST("/register", registerRateLimit, deps.AuthHandler.Register)
	auth.POST("/login", authRateLimit, deps.AuthHandler.Login)
	auth.POST("/refresh", deps.AuthHandler.RefreshToken)
	auth.POST("/forgot-password", resetRateLimit, deps.AuthHandler.ForgotPassword)
	auth.POST("/reset-password", resetRateLimit, deps.AuthHandler.ResetPassword)
	auth.POST("/verify-email", deps.AuthHandler.VerifyEmail)
	auth.POST("/resend-verification", resetRateLimit, deps.AuthHandler.ResendVerification)

	// OAuth routes
	oauth := auth.Group("/oauth")
	{
		oauth.GET("/google", deps.AuthHandler.GoogleOAuth)
		oauth.GET("/google/callback", deps.AuthHandler.GoogleOAuthCallback)
		oauth.GET("/github", deps.AuthHandler.GitHubOAuth)
		oauth.GET("/github/callback", deps.AuthHandler.GitHubOAuthCallback)
	}

	// Protected auth routes
	authenticated := auth.Group("")
	authenticated.Use(deps.AuthMiddleware.RequireAuth())
	{
		authenticated.POST("/logout", deps.AuthHandler.Logout)
		authenticated.POST("/logout-all", deps.AuthHandler.LogoutAll)
		authenticated.POST("/change-password", deps.AuthHandler.ChangePassword)
		authenticated.GET("/me", deps.AuthHandler.GetCurrentUser)
		authenticated.GET("/sessions", deps.AuthHandler.GetActiveSessions)
		authenticated.DELETE("/sessions/:session_id", deps.AuthHandler.RevokeSession)
	}

	// Two-factor authentication
	twoFA := authenticated.Group("/2fa")
	{
		twoFA.POST("/enable", deps.AuthHandler.Enable2FA)
		twoFA.POST("/disable", deps.AuthHandler.Disable2FA)
		twoFA.POST("/verify", deps.AuthHandler.Verify2FA)
		twoFA.GET("/backup-codes", deps.AuthHandler.GetBackupCodes)
		twoFA.POST("/backup-codes/regenerate", deps.AuthHandler.RegenerateBackupCodes)
	}
}
