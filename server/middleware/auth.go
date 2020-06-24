package middleware

import (
	"net/http"
	"os"

	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Authorize authorizes a request
func Authorize(c *gin.Context) {
	tokenString := services.GetTokenFromHeader(c)
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	secret := os.Getenv("JWTSecret") //TODO must change to const
	claims := jwt.MapClaims{}
	token, err := services.VerifyToken(tokenString, claims, secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// set the claims as context parameter.
	// so that the actions can use the claims from jwt token
	c.Set("claims", token.Claims)
	// calling next handler
	c.Next()
}
