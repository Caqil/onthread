package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/repository"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/internal/websocket"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

// AdminHandler handles admin-related HTTP requests
type AdminHandler struct {
	adminRepo        repository.AdminRepository
	userRepo         repository.UserRepository
	threadRepo       repository.ThreadRepository
	analyticsService services.AnalyticsService
	authService      services.AuthService
	userService      services.UserService
	threadService    services.ThreadService
	storageService   services.StorageService
	wsHub            *websocket.Hub
}

// NewAdminHandler creates a new AdminHandler
func NewAdminHandler(
	adminRepo repository.AdminRepository,
	userRepo repository.UserRepository,
	threadRepo repository.ThreadRepository,
	analyticsService services.AnalyticsService,
	authService services.AuthService,
	userService services.UserService,
	threadService services.ThreadService,
	storageService services.StorageService,
	wsHub *websocket.Hub,
) *AdminHandler {
	return &AdminHandler{
		adminRepo:        adminRepo,
		userRepo:         userRepo,
		threadRepo:       threadRepo,
		analyticsService: analyticsService,
		authService:      authService,
		userService:      userService,
		threadService:    threadService,
		storageService:   storageService,
		wsHub:            wsHub,
	}
}

// ===============================
// Admin Authentication Functions
// ===============================

func (h *AdminHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid login credentials")
		return
	}

	admin, token, err := h.authService.AdminLogin(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.Unauthorized(c, "Invalid credentials")
		}
		return
	}

	// Log admin login
	logger.WithFields(map[string]interface{}{
		"admin_id": admin.ID.Hex(),
		"email":    admin.Email,
		"action":   "admin_login",
	}).Info("Admin logged in")

	utils.SuccessResponse(c, http.StatusOK, "Login successful", gin.H{
		"admin": gin.H{
			"id":       admin.ID.Hex(),
			"email":    admin.Email,
			"username": admin.Username,
			"role":     admin.Role,
		},
		"token": token,
	})
}

func (h *AdminHandler) Logout(c *gin.Context) {
	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	// Invalidate admin session
	err := h.authService.AdminLogout(c.Request.Context(), adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to logout")
		return
	}

	logger.WithField("admin_id", adminID).Info("Admin logged out")
	utils.SuccessResponse(c, http.StatusOK, "Logout successful", nil)
}

func (h *AdminHandler) GetCurrentAdmin(c *gin.Context) {
	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	admin, err := h.adminRepo.GetByID(c.Request.Context(), adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get admin details")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin details retrieved", gin.H{
		"id":          admin.ID.Hex(),
		"email":       admin.Email,
		"username":    admin.Username,
		"role":        admin.Role,
		"created_at":  admin.CreatedAt,
		"last_login":  admin.LastLogin,
		"permissions": admin.Permissions,
	})
}

func (h *AdminHandler) ChangePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid password data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.authService.ChangeAdminPassword(c.Request.Context(), adminID.(primitive.ObjectID), req.CurrentPassword, req.NewPassword)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to change password")
		}
		return
	}

	logger.WithField("admin_id", adminID).Info("Admin password changed")
	utils.SuccessResponse(c, http.StatusOK, "Password changed successfully", nil)
}

func (h *AdminHandler) GetAdminSessions(c *gin.Context) {
	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	sessions, err := h.authService.GetAdminSessions(c.Request.Context(), adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get sessions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Sessions retrieved", sessions)
}

func (h *AdminHandler) RevokeAdminSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		utils.BadRequest(c, "Session ID is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.authService.RevokeAdminSession(c.Request.Context(), adminID.(primitive.ObjectID), sessionID)
	if err != nil {
		utils.InternalServerError(c, "Failed to revoke session")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Session revoked successfully", nil)
}

// ===============================
// Dashboard and Analytics Functions
// ===============================

func (h *AdminHandler) GetDashboardStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "7d")

	stats, err := h.analyticsService.GetDashboardStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get dashboard statistics")
		return
	}

	// Add WebSocket stats
	wsStats := h.wsHub.GetStats()
	stats["websocket"] = gin.H{
		"active_connections": wsStats.ActiveConnections,
		"total_users":        wsStats.TotalUsers,
		"rooms_count":        wsStats.RoomsCount,
	}

	utils.SuccessResponse(c, http.StatusOK, "Dashboard statistics retrieved", stats)
}

func (h *AdminHandler) GetSystemMetrics(c *gin.Context) {
	metrics, err := h.analyticsService.GetSystemMetrics(c.Request.Context())
	if err != nil {
		utils.InternalServerError(c, "Failed to get system metrics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "System metrics retrieved", metrics)
}

func (h *AdminHandler) GetRecentActivity(c *gin.Context) {
	utils.GetPaginationParams(c)
	limit := c.DefaultQuery("limit", "50")
	limitInt, _ := strconv.Atoi(limit)

	activity, err := h.analyticsService.GetRecentActivity(c.Request.Context(), limitInt)
	if err != nil {
		utils.InternalServerError(c, "Failed to get recent activity")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Recent activity retrieved", activity)
}

func (h *AdminHandler) GetGrowthMetrics(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	growth, err := h.analyticsService.GetGrowthMetrics(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get growth metrics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Growth metrics retrieved", growth)
}

func (h *AdminHandler) GetEngagementMetrics(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "7d")

	engagement, err := h.analyticsService.GetEngagementMetrics(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get engagement metrics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Engagement metrics retrieved", engagement)
}

// ===============================
// User Management Functions
// ===============================

func (h *AdminHandler) GetAllUsers(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	filter := c.Query("filter")
	search := c.Query("search")
	role := c.Query("role")
	status := c.Query("status")

	result, err := h.userService.GetAllUsersAdmin(c.Request.Context(), params, filter, search, role, status)
	if err != nil {
		utils.InternalServerError(c, "Failed to get users")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Users retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetUserStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	stats, err := h.analyticsService.GetUserStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User statistics retrieved", stats)
}

func (h *AdminHandler) GetUserGrowth(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	growth, err := h.analyticsService.GetUserGrowth(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user growth data")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User growth data retrieved", growth)
}

func (h *AdminHandler) GetVerificationRequests(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	status := c.DefaultQuery("status", "pending")

	requests, err := h.userService.GetVerificationRequests(c.Request.Context(), params, status)
	if err != nil {
		utils.InternalServerError(c, "Failed to get verification requests")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Verification requests retrieved", requests.Data, &utils.Meta{
		Pagination: requests.Pagination,
	})
}

func (h *AdminHandler) ApproveVerification(c *gin.Context) {
	requestID := c.Param("request_id")
	requestOID, err := primitive.ObjectIDFromHex(requestID)
	if err != nil {
		utils.BadRequest(c, "Invalid request ID")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.userService.ApproveVerification(c.Request.Context(), requestOID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to approve verification")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Verification approved successfully", nil)
}

func (h *AdminHandler) RejectVerification(c *gin.Context) {
	requestID := c.Param("request_id")
	requestOID, err := primitive.ObjectIDFromHex(requestID)
	if err != nil {
		utils.BadRequest(c, "Invalid request ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.userService.RejectVerification(c.Request.Context(), requestOID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to reject verification")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Verification rejected successfully", nil)
}

func (h *AdminHandler) GetUserDetails(c *gin.Context) {
	userID := c.Param("user_id")
	userOID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.userService.GetUserDetailsAdmin(c.Request.Context(), userOID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user details")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User details retrieved", user)
}

func (h *AdminHandler) GetUserActivity(c *gin.Context) {
	userID := c.Param("user_id")
	userOID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	params := utils.GetPaginationParams(c)
	timeframe := c.DefaultQuery("timeframe", "30d")

	activity, err := h.analyticsService.GetUserActivity(c.Request.Context(), userOID, params, timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user activity")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User activity retrieved", activity.Data, &utils.Meta{
		Pagination: activity.Pagination,
	})
}

func (h *AdminHandler) GetUserReports(c *gin.Context) {
	userID := c.Param("user_id")
	userOID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	params := utils.GetPaginationParams(c)

	reports, err := h.analyticsService.GetUserReports(c.Request.Context(), userOID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user reports")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User reports retrieved", reports.Data, &utils.Meta{
		Pagination: reports.Pagination,
	})
}

func (h *AdminHandler) TakeUserAction(c *gin.Context) {
	userID := c.Param("user_id")
	userOID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		Action   string `json:"action" binding:"required"`
		Reason   string `json:"reason" binding:"required"`
		Duration int    `json:"duration"` // in hours for temporary actions
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Action and reason are required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.userService.TakeUserAction(c.Request.Context(), userOID, adminID.(primitive.ObjectID), req.Action, req.Reason, req.Duration)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to take user action")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User action taken successfully", nil)
}

func (h *AdminHandler) GetUserActionHistory(c *gin.Context) {
	userID := c.Param("user_id")
	userOID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	params := utils.GetPaginationParams(c)

	history, err := h.userService.GetUserActionHistory(c.Request.Context(), userOID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user action history")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User action history retrieved", history.Data, &utils.Meta{
		Pagination: history.Pagination,
	})
}

// ===============================
// Content Management Functions
// ===============================

func (h *AdminHandler) GetAllThreads(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	filter := c.Query("filter")
	search := c.Query("search")

	result, err := h.threadService.GetAllThreadsAdmin(c.Request.Context(), params, filter, search)
	if err != nil {
		utils.InternalServerError(c, "Failed to get threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetContentStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	stats, err := h.analyticsService.GetContentStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get content statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content statistics retrieved", stats)
}

func (h *AdminHandler) GetReportedContent(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	contentType := c.Query("type")

	result, err := h.threadService.GetReportedContent(c.Request.Context(), params, contentType)
	if err != nil {
		utils.InternalServerError(c, "Failed to get reported content")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Reported content retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetFlaggedContent(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	contentType := c.Query("type")

	result, err := h.threadService.GetFlaggedContent(c.Request.Context(), params, contentType)
	if err != nil {
		utils.InternalServerError(c, "Failed to get flagged content")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Flagged content retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) TakeContentAction(c *gin.Context) {
	threadID := c.Param("thread_id")
	threadOID, err := primitive.ObjectIDFromHex(threadID)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Action string `json:"action" binding:"required"`
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Action and reason are required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.TakeContentAction(c.Request.Context(), threadOID, adminID.(primitive.ObjectID), req.Action, req.Reason)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to take content action")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content action taken successfully", nil)
}

func (h *AdminHandler) GetHashtags(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	search := c.Query("search")
	status := c.Query("status")

	result, err := h.threadService.GetHashtags(c.Request.Context(), params, search, status)
	if err != nil {
		utils.InternalServerError(c, "Failed to get hashtags")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Hashtags retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetTrendingHashtags(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "24h")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	hashtags, err := h.threadService.GetTrendingHashtags(c.Request.Context(), timeframe, limit)
	if err != nil {
		utils.InternalServerError(c, "Failed to get trending hashtags")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Trending hashtags retrieved", hashtags)
}

func (h *AdminHandler) BlockHashtag(c *gin.Context) {
	hashtag := c.Param("hashtag")

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.threadService.BlockHashtag(c.Request.Context(), hashtag, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to block hashtag")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Hashtag blocked successfully", nil)
}

func (h *AdminHandler) UnblockHashtag(c *gin.Context) {
	hashtag := c.Param("hashtag")

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.threadService.UnblockHashtag(c.Request.Context(), hashtag, adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to unblock hashtag")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Hashtag unblocked successfully", nil)
}

// ===============================
// WebSocket Management Functions
// ===============================

func (h *AdminHandler) GetWebSocketStats(c *gin.Context) {
	stats := h.wsHub.GetStats()

	detailedStats := gin.H{
		"active_connections":  stats.ActiveConnections,
		"total_users":         stats.TotalUsers,
		"rooms_count":         stats.RoomsCount,
		"messages_sent":       stats.MessagesSent,
		"messages_received":   stats.MessagesReceived,
		"connections_by_hour": stats.ConnectionsByHour,
		"users_by_activity":   stats.UsersByActivity,
		"last_updated":        stats.LastUpdated,
		"uptime":              time.Since(stats.LastUpdated),
	}

	utils.SuccessResponse(c, http.StatusOK, "WebSocket statistics retrieved", detailedStats)
}

func (h *AdminHandler) GetActiveConnections(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	userID := c.Query("user_id")
	activity := c.Query("activity")

	connections := h.wsHub.GetActiveConnections(userID, activity)

	// Apply pagination
	start := (params.Page - 1) * params.Limit
	end := start + params.Limit

	if start > len(connections) {
		start = len(connections)
	}
	if end > len(connections) {
		end = len(connections)
	}

	paginatedConnections := connections[start:end]

	connectionDetails := make([]gin.H, len(paginatedConnections))
	for i, conn := range paginatedConnections {
		connectionDetails[i] = gin.H{
			"connection_id":   conn.ID,
			"user_id":         conn.UserID.Hex(),
			"username":        conn.Username,
			"connected_at":    conn.ConnectedAt,
			"last_activity":   conn.LastActivity,
			"is_online":       conn.IsOnline,
			"current_rooms":   conn.GetRooms(),
			"ip_address":      conn.RemoteAddr,
			"user_agent":      conn.UserAgent,
			"connection_type": conn.ConnectionType,
		}
	}

	pagination := &utils.Pagination{
		Page:        params.Page,
		Limit:       params.Limit,
		Total:       int64(len(connections)),
		TotalPages:  (len(connections) + params.Limit - 1) / params.Limit,
		HasNext:     end < len(connections),
		HasPrevious: start > 0,
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Active connections retrieved", connectionDetails, &utils.Meta{
		Pagination: pagination,
	})
}

func (h *AdminHandler) DisconnectUser(c *gin.Context) {
	connectionID := c.Param("connection_id")
	if connectionID == "" {
		utils.BadRequest(c, "Connection ID is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin authentication required")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	success := h.wsHub.DisconnectUser(connectionID)
	if !success {
		utils.NotFound(c, "Connection not found or already disconnected")
		return
	}

	logger.WithFields(map[string]interface{}{
		"admin_id":      adminID,
		"connection_id": connectionID,
		"reason":        req.Reason,
		"action":        "force_disconnect",
	}).Info("Admin forcefully disconnected user")

	utils.SuccessResponse(c, http.StatusOK, "User disconnected successfully", gin.H{
		"connection_id": connectionID,
		"reason":        req.Reason,
		"timestamp":     time.Now(),
	})
}

func (h *AdminHandler) BroadcastMessage(c *gin.Context) {
	var req struct {
		Type      string                 `json:"type" binding:"required"`
		Title     string                 `json:"title" binding:"required"`
		Content   string                 `json:"content" binding:"required"`
		Priority  string                 `json:"priority"`
		Target    string                 `json:"target"`
		TargetID  string                 `json:"target_id"`
		Metadata  map[string]interface{} `json:"metadata"`
		ExpiresAt *time.Time             `json:"expires_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin authentication required")
		return
	}

	if req.Priority == "" {
		req.Priority = "medium"
	}
	if req.Target == "" {
		req.Target = "all"
	}

	message := websocket.CreateSystemMessage(req.Title, req.Content, req.Type, req.Priority)

	if req.Metadata != nil {
		if systemMsg, ok := message.Data.(*websocket.SystemMessage); ok {
			systemMsg.Metadata = req.Metadata
			systemMsg.ExpiresAt = req.ExpiresAt
		}
	}

	var excludeUser primitive.ObjectID
	switch req.Target {
	case "all":
		h.wsHub.BroadcastToAll(message)
	case "user":
		if req.TargetID == "" {
			utils.BadRequest(c, "Target user ID is required")
			return
		}
		userID, err := primitive.ObjectIDFromHex(req.TargetID)
		if err != nil {
			utils.BadRequest(c, "Invalid user ID")
			return
		}
		h.wsHub.BroadcastToUser(userID, message)
	case "room":
		if req.TargetID == "" {
			utils.BadRequest(c, "Target room ID is required")
			return
		}
		h.wsHub.BroadcastToRoom(req.TargetID, message, excludeUser)
	default:
		utils.BadRequest(c, "Invalid target type")
		return
	}

	logger.WithFields(map[string]interface{}{
		"admin_id":  adminID,
		"type":      req.Type,
		"target":    req.Target,
		"target_id": req.TargetID,
		"priority":  req.Priority,
		"action":    "admin_broadcast",
	}).Info("Admin broadcasted message")

	utils.SuccessResponse(c, http.StatusOK, "Message broadcasted successfully", gin.H{
		"message_id": message.MessageID,
		"target":     req.Target,
		"target_id":  req.TargetID,
		"timestamp":  time.Now(),
	})
}

func (h *AdminHandler) GetWebSocketRooms(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	roomType := c.Query("type")
	minUsers, _ := strconv.Atoi(c.Query("min_users"))

	rooms := h.wsHub.GetRooms(roomType, minUsers)

	start := (params.Page - 1) * params.Limit
	end := start + params.Limit

	if start > len(rooms) {
		start = len(rooms)
	}
	if end > len(rooms) {
		end = len(rooms)
	}

	paginatedRooms := rooms[start:end]

	roomDetails := make([]gin.H, len(paginatedRooms))
	for i, room := range paginatedRooms {
		roomDetails[i] = gin.H{
			"room_id":       room.ID,
			"room_type":     room.Type,
			"name":          room.Name,
			"user_count":    room.UserCount,
			"created_at":    room.CreatedAt,
			"last_activity": room.LastActivity,
			"is_active":     room.IsActive,
			"metadata":      room.Metadata,
		}
	}

	pagination := &utils.Pagination{
		Page:        params.Page,
		Limit:       params.Limit,
		Total:       int64(len(rooms)),
		TotalPages:  (len(rooms) + params.Limit - 1) / params.Limit,
		HasNext:     end < len(rooms),
		HasPrevious: start > 0,
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "WebSocket rooms retrieved", roomDetails, &utils.Meta{
		Pagination: pagination,
	})
}

// ===============================
// Reports and Moderation Functions
// ===============================

func (h *AdminHandler) GetAllReports(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	status := c.Query("status")
	reportType := c.Query("type")
	priority := c.Query("priority")

	result, err := h.analyticsService.GetAllReports(c.Request.Context(), params, status, reportType, priority)
	if err != nil {
		utils.InternalServerError(c, "Failed to get reports")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Reports retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetReportStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	stats, err := h.analyticsService.GetReportStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get report statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Report statistics retrieved", stats)
}

func (h *AdminHandler) GetReportDetails(c *gin.Context) {
	reportID := c.Param("report_id")
	reportOID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.BadRequest(c, "Invalid report ID")
		return
	}

	report, err := h.analyticsService.GetReportDetails(c.Request.Context(), reportOID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get report details")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Report details retrieved", report)
}

func (h *AdminHandler) ReviewReport(c *gin.Context) {
	reportID := c.Param("report_id")
	reportOID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.BadRequest(c, "Invalid report ID")
		return
	}

	var req struct {
		Status string `json:"status" binding:"required,oneof=reviewing resolved dismissed"`
		Notes  string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid status is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.analyticsService.ReviewReport(c.Request.Context(), reportOID, adminID.(primitive.ObjectID), req.Status, req.Notes)
	if err != nil {
		utils.InternalServerError(c, "Failed to review report")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Report reviewed successfully", nil)
}

func (h *AdminHandler) ResolveReport(c *gin.Context) {
	reportID := c.Param("report_id")
	reportOID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.BadRequest(c, "Invalid report ID")
		return
	}

	var req struct {
		Action     string `json:"action" binding:"required"`
		Resolution string `json:"resolution" binding:"required"`
		Notes      string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Action and resolution are required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.analyticsService.ResolveReport(c.Request.Context(), reportOID, adminID.(primitive.ObjectID), req.Action, req.Resolution, req.Notes)
	if err != nil {
		utils.InternalServerError(c, "Failed to resolve report")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Report resolved successfully", nil)
}

func (h *AdminHandler) DismissReport(c *gin.Context) {
	reportID := c.Param("report_id")
	reportOID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.BadRequest(c, "Invalid report ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
		Notes  string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.analyticsService.DismissReport(c.Request.Context(), reportOID, adminID.(primitive.ObjectID), req.Reason, req.Notes)
	if err != nil {
		utils.InternalServerError(c, "Failed to dismiss report")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Report dismissed successfully", nil)
}

func (h *AdminHandler) GetModerationActions(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	actionType := c.Query("type")
	adminID := c.Query("admin_id")

	result, err := h.analyticsService.GetModerationActions(c.Request.Context(), params, actionType, adminID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get moderation actions")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Moderation actions retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) GetModerationStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	stats, err := h.analyticsService.GetModerationStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get moderation statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Moderation statistics retrieved", stats)
}

func (h *AdminHandler) ReverseModerationAction(c *gin.Context) {
	actionID := c.Param("action_id")
	actionOID, err := primitive.ObjectIDFromHex(actionID)
	if err != nil {
		utils.BadRequest(c, "Invalid action ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.analyticsService.ReverseModerationAction(c.Request.Context(), actionOID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to reverse moderation action")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Moderation action reversed successfully", nil)
}

// ===============================
// System Configuration Functions
// ===============================

func (h *AdminHandler) GetSystemConfig(c *gin.Context) {
	config, err := h.analyticsService.GetSystemConfig(c.Request.Context())
	if err != nil {
		utils.InternalServerError(c, "Failed to get system configuration")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "System configuration retrieved", config)
}

func (h *AdminHandler) UpdateSystemConfig(c *gin.Context) {
	var req map[string]interface{}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid configuration data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.analyticsService.UpdateSystemConfig(c.Request.Context(), adminID.(primitive.ObjectID), req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update system configuration")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "System configuration updated successfully", nil)
}

func (h *AdminHandler) GetConfigValue(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		utils.BadRequest(c, "Configuration key is required")
		return
	}

	value, err := h.analyticsService.GetConfigValue(c.Request.Context(), key)
	if err != nil {
		utils.InternalServerError(c, "Failed to get configuration value")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Configuration value retrieved", gin.H{
		"key":   key,
		"value": value,
	})
}

func (h *AdminHandler) UpdateConfigValue(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		utils.BadRequest(c, "Configuration key is required")
		return
	}

	var req struct {
		Value interface{} `json:"value" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Configuration value is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.analyticsService.UpdateConfigValue(c.Request.Context(), adminID.(primitive.ObjectID), key, req.Value)
	if err != nil {
		utils.InternalServerError(c, "Failed to update configuration value")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Configuration value updated successfully", nil)
}

func (h *AdminHandler) GetFeatureFlags(c *gin.Context) {
	flags, err := h.analyticsService.GetFeatureFlags(c.Request.Context())
	if err != nil {
		utils.InternalServerError(c, "Failed to get feature flags")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Feature flags retrieved", flags)
}

func (h *AdminHandler) UpdateFeatureFlag(c *gin.Context) {
	feature := c.Param("feature")
	if feature == "" {
		utils.BadRequest(c, "Feature name is required")
		return
	}

	var req struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid feature flag data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.analyticsService.UpdateFeatureFlag(c.Request.Context(), adminID.(primitive.ObjectID), feature, req.Enabled, req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to update feature flag")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Feature flag updated successfully", nil)
}

func (h *AdminHandler) GetMaintenanceStatus(c *gin.Context) {
	status, err := h.analyticsService.GetMaintenanceStatus(c.Request.Context())
	if err != nil {
		utils.InternalServerError(c, "Failed to get maintenance status")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Maintenance status retrieved", status)
}

func (h *AdminHandler) EnableMaintenance(c *gin.Context) {
	var req struct {
		Message   string     `json:"message" binding:"required"`
		StartTime *time.Time `json:"start_time"`
		EndTime   *time.Time `json:"end_time"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Maintenance message is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.analyticsService.EnableMaintenance(c.Request.Context(), adminID.(primitive.ObjectID), req.Message, req.StartTime, req.EndTime)
	if err != nil {
		utils.InternalServerError(c, "Failed to enable maintenance mode")
		return
	}

	// Broadcast maintenance notification to all connected users
	maintenanceMsg := websocket.CreateSystemMessage(
		"Maintenance Mode",
		req.Message,
		"maintenance",
		"high",
	)
	h.wsHub.BroadcastToAll(maintenanceMsg)

	utils.SuccessResponse(c, http.StatusOK, "Maintenance mode enabled successfully", nil)
}

func (h *AdminHandler) DisableMaintenance(c *gin.Context) {
	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.analyticsService.DisableMaintenance(c.Request.Context(), adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to disable maintenance mode")
		return
	}

	// Broadcast maintenance end notification
	endMsg := websocket.CreateSystemMessage(
		"Maintenance Complete",
		"The system is now fully operational",
		"maintenance_end",
		"medium",
	)
	h.wsHub.BroadcastToAll(endMsg)

	utils.SuccessResponse(c, http.StatusOK, "Maintenance mode disabled successfully", nil)
}

// ===============================
// Storage Management Functions
// ===============================

func (h *AdminHandler) GetStorageStats(c *gin.Context) {
	stats, err := h.storageService.GetStorageStats(c.Request.Context())
	if err != nil {
		utils.InternalServerError(c, "Failed to get storage statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Storage statistics retrieved", stats)
}

func (h *AdminHandler) GetStorageFiles(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	fileType := c.Query("type")
	userId := c.Query("user_id")

	result, err := h.storageService.GetStorageFiles(c.Request.Context(), params, fileType, userId)
	if err != nil {
		utils.InternalServerError(c, "Failed to get storage files")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Storage files retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) DeleteStorageFile(c *gin.Context) {
	fileID := c.Param("file_id")
	if fileID == "" {
		utils.BadRequest(c, "File ID is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	err := h.storageService.DeleteFile(c.Request.Context(), fileID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to delete file")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "File deleted successfully", nil)
}

func (h *AdminHandler) CleanupStorage(c *gin.Context) {
	var req struct {
		DryRun    bool `json:"dry_run"`
		OlderThan int  `json:"older_than"` // days
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		req.DryRun = true
		req.OlderThan = 30
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	result, err := h.storageService.CleanupStorage(c.Request.Context(), adminID.(primitive.ObjectID), req.DryRun, req.OlderThan)
	if err != nil {
		utils.InternalServerError(c, "Failed to cleanup storage")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Storage cleanup completed", result)
}

func (h *AdminHandler) GetStorageUsage(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")
	groupBy := c.DefaultQuery("group_by", "day")

	usage, err := h.storageService.GetStorageUsage(c.Request.Context(), timeframe, groupBy)
	if err != nil {
		utils.InternalServerError(c, "Failed to get storage usage")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Storage usage retrieved", usage)
}

func (h *AdminHandler) UpdateStorageSettings(c *gin.Context) {
	var req struct {
		MaxFileSize      int64    `json:"max_file_size"`
		AllowedTypes     []string `json:"allowed_types"`
		CompressionLevel int      `json:"compression_level"`
		RetentionPeriod  int      `json:"retention_period"` // days
		AutoCleanup      bool     `json:"auto_cleanup"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid storage settings")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err := h.storageService.UpdateSettings(c.Request.Context(), adminID.(primitive.ObjectID), req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update storage settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Storage settings updated successfully", nil)
}

// ===============================
// Admin Management Functions
// ===============================

func (h *AdminHandler) GetAllAdmins(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	role := c.Query("role")
	status := c.Query("status")

	result, err := h.adminRepo.GetAllAdmins(c.Request.Context(), params, role, status)
	if err != nil {
		utils.InternalServerError(c, "Failed to get admins")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Admins retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) CreateAdmin(c *gin.Context) {
	var req struct {
		Email       string   `json:"email" binding:"required,email"`
		Username    string   `json:"username" binding:"required"`
		Password    string   `json:"password" binding:"required,min=8"`
		Role        string   `json:"role" binding:"required,oneof=admin moderator support"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid admin data")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	admin, err := h.adminRepo.CreateAdmin(c.Request.Context(), currentAdminID.(primitive.ObjectID), req)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to create admin")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Admin created successfully", gin.H{
		"id":       admin.ID.Hex(),
		"email":    admin.Email,
		"username": admin.Username,
		"role":     admin.Role,
	})
}

func (h *AdminHandler) GetAdminDetails(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	admin, err := h.adminRepo.GetAdminDetails(c.Request.Context(), adminOID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get admin details")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin details retrieved", admin)
}

func (h *AdminHandler) UpdateAdmin(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	var req struct {
		Email       string   `json:"email"`
		Username    string   `json:"username"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
		Status      string   `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid admin data")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.adminRepo.UpdateAdmin(c.Request.Context(), adminOID, currentAdminID.(primitive.ObjectID), req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update admin")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin updated successfully", nil)
}

func (h *AdminHandler) DeleteAdmin(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.adminRepo.DeleteAdmin(c.Request.Context(), adminOID, currentAdminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to delete admin")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin deleted successfully", nil)
}

func (h *AdminHandler) ActivateAdmin(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.adminRepo.ActivateAdmin(c.Request.Context(), adminOID, currentAdminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to activate admin")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin activated successfully", nil)
}

func (h *AdminHandler) DeactivateAdmin(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.adminRepo.DeactivateAdmin(c.Request.Context(), adminOID, currentAdminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to deactivate admin")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin deactivated successfully", nil)
}

func (h *AdminHandler) GetAdminActivity(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	params := utils.GetPaginationParams(c)
	timeframe := c.DefaultQuery("timeframe", "30d")

	activity, err := h.analyticsService.GetAdminActivity(c.Request.Context(), adminOID, params, timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get admin activity")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Admin activity retrieved", activity.Data, &utils.Meta{
		Pagination: activity.Pagination,
	})
}

func (h *AdminHandler) UpdateAdminPermissions(c *gin.Context) {
	adminID := c.Param("admin_id")
	adminOID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		utils.BadRequest(c, "Invalid admin ID")
		return
	}

	var req struct {
		Permissions []string `json:"permissions" binding:"required"`
		Reason      string   `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Permissions are required")
		return
	}

	currentAdminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.adminRepo.UpdateAdminPermissions(c.Request.Context(), adminOID, currentAdminID.(primitive.ObjectID), req.Permissions, req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to update admin permissions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Admin permissions updated successfully", nil)
}

// ===============================
// Audit Logs Functions
// ===============================

func (h *AdminHandler) GetAuditLogs(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	action := c.Query("action")
	adminID := c.Query("admin_id")
	resourceType := c.Query("resource_type")
	timeframe := c.DefaultQuery("timeframe", "30d")

	result, err := h.analyticsService.GetAuditLogs(c.Request.Context(), params, action, adminID, resourceType, timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get audit logs")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Audit logs retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) ExportAuditLogs(c *gin.Context) {
	exportFormat := c.DefaultQuery("format", "csv")
	timeframe := c.DefaultQuery("timeframe", "30d")
	action := c.Query("action")
	adminID := c.Query("admin_id")

	exportData, err := h.analyticsService.ExportAuditLogs(c.Request.Context(), exportFormat, timeframe, action, adminID)
	if err != nil {
		utils.InternalServerError(c, "Failed to export audit logs")
		return
	}

	filename := fmt.Sprintf("audit_logs_%s.%s", time.Now().Format("2006-01-02"), exportFormat)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch exportFormat {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	case "xlsx":
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), exportData)
}

func (h *AdminHandler) GetAuditStats(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "30d")

	stats, err := h.analyticsService.GetAuditStats(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get audit statistics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Audit statistics retrieved", stats)
}

// ===============================
// Content Filters Functions
// ===============================

func (h *AdminHandler) GetContentFilters(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	filterType := c.Query("type")
	status := c.Query("status")

	result, err := h.threadService.GetContentFilters(c.Request.Context(), params, filterType, status)
	if err != nil {
		utils.InternalServerError(c, "Failed to get content filters")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Content filters retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *AdminHandler) CreateContentFilter(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Type        string   `json:"type" binding:"required"`
		Pattern     string   `json:"pattern" binding:"required"`
		Action      string   `json:"action" binding:"required"`
		Severity    string   `json:"severity" binding:"required"`
		Keywords    []string `json:"keywords"`
		Description string   `json:"description"`
		IsActive    bool     `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid content filter data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	filter, err := h.threadService.CreateContentFilter(c.Request.Context(), adminID.(primitive.ObjectID), req)
	if err != nil {
		utils.InternalServerError(c, "Failed to create content filter")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Content filter created successfully", filter)
}

func (h *AdminHandler) GetContentFilter(c *gin.Context) {
	filterID := c.Param("filter_id")
	filterOID, err := primitive.ObjectIDFromHex(filterID)
	if err != nil {
		utils.BadRequest(c, "Invalid filter ID")
		return
	}

	filter, err := h.threadService.GetContentFilter(c.Request.Context(), filterOID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get content filter")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content filter retrieved", filter)
}

func (h *AdminHandler) UpdateContentFilter(c *gin.Context) {
	filterID := c.Param("filter_id")
	filterOID, err := primitive.ObjectIDFromHex(filterID)
	if err != nil {
		utils.BadRequest(c, "Invalid filter ID")
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Pattern     string   `json:"pattern"`
		Action      string   `json:"action"`
		Severity    string   `json:"severity"`
		Keywords    []string `json:"keywords"`
		Description string   `json:"description"`
		IsActive    bool     `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid content filter data")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.UpdateContentFilter(c.Request.Context(), filterOID, adminID.(primitive.ObjectID), req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update content filter")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content filter updated successfully", nil)
}

func (h *AdminHandler) DeleteContentFilter(c *gin.Context) {
	filterID := c.Param("filter_id")
	filterOID, err := primitive.ObjectIDFromHex(filterID)
	if err != nil {
		utils.BadRequest(c, "Invalid filter ID")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.DeleteContentFilter(c.Request.Context(), filterOID, adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to delete content filter")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content filter deleted successfully", nil)
}

func (h *AdminHandler) TestContentFilter(c *gin.Context) {
	filterID := c.Param("filter_id")
	filterOID, err := primitive.ObjectIDFromHex(filterID)
	if err != nil {
		utils.BadRequest(c, "Invalid filter ID")
		return
	}

	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Content is required for testing")
		return
	}

	result, err := h.threadService.TestContentFilter(c.Request.Context(), filterOID, req.Content)
	if err != nil {
		utils.InternalServerError(c, "Failed to test content filter")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content filter test completed", result)
}

func (h *AdminHandler) GetFilterMatches(c *gin.Context) {
	filterID := c.Param("filter_id")
	filterOID, err := primitive.ObjectIDFromHex(filterID)
	if err != nil {
		utils.BadRequest(c, "Invalid filter ID")
		return
	}

	params := utils.GetPaginationParams(c)
	timeframe := c.DefaultQuery("timeframe", "7d")

	result, err := h.threadService.GetFilterMatches(c.Request.Context(), filterOID, params, timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get filter matches")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Filter matches retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// ===============================
// Analytics Functions (Already implemented above)
// ===============================

func (h *AdminHandler) GetAnalyticsOverview(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "7d")

	overview, err := h.analyticsService.GetAnalyticsOverview(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get analytics overview")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Analytics overview retrieved", overview)
}

func (h *AdminHandler) GetUserAnalytics(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "7d")

	analytics, err := h.analyticsService.GetUserAnalytics(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user analytics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User analytics retrieved", analytics)
}

func (h *AdminHandler) GetContentAnalytics(c *gin.Context) {
	timeframe := c.DefaultQuery("timeframe", "7d")

	analytics, err := h.analyticsService.GetContentAnalytics(c.Request.Context(), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get content analytics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Content analytics retrieved", analytics)
}

func (h *AdminHandler) GetAnalyticsReports(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	reportType := c.Query("type")

	reports, err := h.analyticsService.GetAnalyticsReports(c.Request.Context(), params, reportType)
	if err != nil {
		utils.InternalServerError(c, "Failed to get analytics reports")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Analytics reports retrieved", reports.Data, &utils.Meta{
		Pagination: reports.Pagination,
	})
}

func (h *AdminHandler) ExportAnalytics(c *gin.Context) {
	exportType := c.DefaultQuery("type", "csv")
	timeframe := c.DefaultQuery("timeframe", "30d")
	dataType := c.DefaultQuery("data_type", "overview")

	exportData, err := h.analyticsService.ExportAnalyticsData(c.Request.Context(), dataType, timeframe, exportType)
	if err != nil {
		utils.InternalServerError(c, "Failed to export analytics data")
		return
	}

	filename := fmt.Sprintf("analytics_%s_%s.%s", dataType, time.Now().Format("2006-01-02"), exportType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch exportType {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	case "xlsx":
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), exportData)
}
