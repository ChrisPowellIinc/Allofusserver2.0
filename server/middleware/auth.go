package middleware

import (
	"log"
	"net/http"
	"os"

	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/gin-gonic/gin"
)

// Authorize authorizes a request
func Authorize(c *gin.Context) {
	claims, err := services.AuthorizeAndGetClaims(c, os.Getenv("JWTSecret"))
	if err != nil {
		log.Printf("%v\n", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}

	// set the claims as context parameter.
	// so that the actions can use the claims from jwt token
	c.Set("claims", claims)
	// calling next handler
	c.Next()
}
