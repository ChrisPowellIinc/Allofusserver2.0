package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{
			"message": "signup successful",
		})
	}
}

func (s *Server) handleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "login successful",
		})
	}
}
