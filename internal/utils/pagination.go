package utils

import (
	"math"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
	MinLimit     = 1
)

type PaginationParams struct {
	Page   int    `json:"page" form:"page"`
	Limit  int    `json:"limit" form:"limit"`
	Sort   string `json:"sort" form:"sort"`
	Order  string `json:"order" form:"order"`
	Search string `json:"search" form:"search"`
	Filter string `json:"filter" form:"filter"`
}

type PaginationResult struct {
	Data       interface{}     `json:"data"`
	Pagination *PaginationMeta `json:"pagination"`
	Sorting    *SortingMeta    `json:"sorting,omitempty"`
}

type SortParams struct {
	Field string
	Order int // 1 for ascending, -1 for descending
}

// GetPaginationParams extracts pagination parameters from Gin context
func GetPaginationParams(c *gin.Context) *PaginationParams {
	page := getIntParam(c, "page", DefaultPage)
	limit := getIntParam(c, "limit", DefaultLimit)

	// Validate and clamp values
	if page < 1 {
		page = DefaultPage
	}
	if limit < MinLimit {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	sort := c.DefaultQuery("sort", "created_at")
	order := c.DefaultQuery("order", "desc")
	search := c.Query("search")
	filter := c.Query("filter")

	return &PaginationParams{
		Page:   page,
		Limit:  limit,
		Sort:   sort,
		Order:  order,
		Search: search,
		Filter: filter,
	}
}

// GetMongoOptions returns MongoDB options for pagination and sorting
func (p *PaginationParams) GetMongoOptions() *options.FindOptions {
	opts := options.Find()

	// Set pagination
	skip := int64((p.Page - 1) * p.Limit)
	opts.SetSkip(skip)
	opts.SetLimit(int64(p.Limit))

	// Set sorting
	sortOrder := 1
	if p.Order == "desc" {
		sortOrder = -1
	}

	opts.SetSort(bson.D{{Key: p.Sort, Value: sortOrder}})

	return opts
}

// GetSortParams returns sorting parameters for MongoDB
func (p *PaginationParams) GetSortParams() SortParams {
	order := 1
	if p.Order == "desc" {
		order = -1
	}

	return SortParams{
		Field: p.Sort,
		Order: order,
	}
}

// BuildSearchFilter builds MongoDB filter for search functionality
func (p *PaginationParams) BuildSearchFilter(searchFields []string) bson.M {
	filter := bson.M{}

	if p.Search != "" && len(searchFields) > 0 {
		searchConditions := make([]bson.M, 0, len(searchFields))

		for _, field := range searchFields {
			searchConditions = append(searchConditions, bson.M{
				field: bson.M{
					"$regex":   p.Search,
					"$options": "i", // case insensitive
				},
			})
		}

		filter["$or"] = searchConditions
	}

	return filter
}

// BuildFilterConditions builds MongoDB filter from filter string
func (p *PaginationParams) BuildFilterConditions() bson.M {
	// This is a basic implementation. You can extend this based on your needs
	filter := bson.M{}

	// Add common filters
	if p.Filter != "" {
		// Parse filter string (e.g., "status:active,type:thread")
		// This is a simple implementation - you might want to use a more sophisticated parser
		// For now, we'll keep it simple
	}

	return filter
}

// CalculatePaginationMeta calculates pagination metadata
func CalculatePaginationMeta(page, limit int, totalItems int64) *PaginationMeta {
	totalPages := int(math.Ceil(float64(totalItems) / float64(limit)))

	hasNext := page < totalPages
	hasPrev := page > 1

	var nextPage, prevPage *int
	if hasNext {
		next := page + 1
		nextPage = &next
	}
	if hasPrev {
		prev := page - 1
		prevPage = &prev
	}

	return &PaginationMeta{
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
		TotalItems: totalItems,
		HasNext:    hasNext,
		HasPrev:    hasPrev,
		NextPage:   nextPage,
		PrevPage:   prevPage,
	}
}

// CreatePaginationResult creates a complete pagination result
func CreatePaginationResult(data interface{}, params *PaginationParams, totalItems int64) *PaginationResult {
	paginationMeta := CalculatePaginationMeta(params.Page, params.Limit, totalItems)

	var sortingMeta *SortingMeta
	if params.Sort != "" {
		sortingMeta = &SortingMeta{
			Field: params.Sort,
			Order: params.Order,
		}
	}

	return &PaginationResult{
		Data:       data,
		Pagination: paginationMeta,
		Sorting:    sortingMeta,
	}
}

// Helper function to get int parameter from context
func getIntParam(c *gin.Context, key string, defaultValue int) int {
	if value := c.Query(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// CursorPagination for more efficient pagination with large datasets
type CursorParams struct {
	Cursor string `json:"cursor" form:"cursor"`
	Limit  int    `json:"limit" form:"limit"`
	Sort   string `json:"sort" form:"sort"`
	Order  string `json:"order" form:"order"`
}

type CursorResult struct {
	Data       interface{} `json:"data"`
	NextCursor *string     `json:"next_cursor,omitempty"`
	PrevCursor *string     `json:"prev_cursor,omitempty"`
	HasNext    bool        `json:"has_next"`
	HasPrev    bool        `json:"has_prev"`
}

// GetCursorParams extracts cursor pagination parameters
func GetCursorParams(c *gin.Context) *CursorParams {
	limit := getIntParam(c, "limit", DefaultLimit)
	if limit > MaxLimit {
		limit = MaxLimit
	}

	return &CursorParams{
		Cursor: c.Query("cursor"),
		Limit:  limit,
		Sort:   c.DefaultQuery("sort", "created_at"),
		Order:  c.DefaultQuery("order", "desc"),
	}
}
