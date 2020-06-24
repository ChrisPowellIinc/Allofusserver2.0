package middleware

import (
	"net/http"

	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func Authorize(c *gin.Context) {
	tokenString, err := services.GetTokenFromHeader(c)
	// if error on getting the token, return with status unauthorized
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	secret := "JWTSecret"
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
