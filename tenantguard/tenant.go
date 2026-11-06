// Package tenantguard is the shared merchant-isolation helper for r2day APIs.
//
// It is NOT the same as middle's super-domain switcher (middle/tenant.go).
// Tenant identity for isolation trusts ONLY the JWT-written X-Tenant-ID header
// (see also rest.IsolateMerchantIDStrict).
//
// Migrate from duplicated */internal/tenant by importing this package.
package tenantguard

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open4go/middle"
)

// errResp mirrors open4go/rest.ErrResp without importing rest (avoids module cycle).
type errResp struct {
	Title     string `json:"title"`
	Message   string `json:"message"`
	Status    string `json:"status"`
	RequestID string `json:"request_id"`
	Redirect  string `json:"redirect"`
}

func requestID(c *gin.Context) string {
	if c == nil {
		return "Unknown"
	}
	if v, ok := c.Get("RequestID"); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "Unknown"
}

func abortJSON(c *gin.Context, code int, title, message string) {
	status := "fail"
	if code >= 500 {
		status = "error"
	}
	c.JSON(code, errResp{
		Title:     title,
		Message:   message,
		Status:    status,
		RequestID: requestID(c),
	})
	c.Abort()
}

// ID returns the merchant for this request (JWTMiddleware writes X-Tenant-ID).
func ID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
}

// Merchant returns the merchant used for query filters; empty means verified
// super-admin "view all". Only reads JWT-written X-Tenant-ID (no X-Merchant-ID fallback).
func Merchant(c *gin.Context) string {
	id := ID(c)
	if id == "*" {
		return ""
	}
	return id
}

// Require rejects requests with no merchant context unless the caller is a
// verified super-admin (prevents unscoped list/stats leakage).
func Require() gin.HandlerFunc {
	return func(c *gin.Context) {
		if Merchant(c) == "" && !middle.IsSuperAdmin(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// Owns reports whether the login may access owner without writing a response.
func Owns(c *gin.Context, owner string) bool {
	t := ID(c)
	if t == "" || t == "*" {
		return middle.IsSuperAdmin(c)
	}
	return strings.TrimSpace(owner) == t
}

// Allow is Owns; on failure writes 404 and aborts.
func Allow(c *gin.Context, owner string) bool {
	if Owns(c, owner) {
		return true
	}
	abortJSON(c, http.StatusNotFound, "不存在", "not found")
	return false
}

// SuperOnly allows only verified super-admins; otherwise 403.
func SuperOnly(c *gin.Context) bool {
	if middle.IsSuperAdmin(c) {
		return true
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	return false
}
