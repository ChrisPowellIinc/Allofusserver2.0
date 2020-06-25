package services

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// GetTokenFromHeader returns the token string in the authorization header
func GetTokenFromHeader(c *gin.Context) string {
	authHeader := c.Request.Header.Get("Authorization")
	return authHeader[7:]
}

//TODO more research on verifying tokens

// VerifyToken verifies a token
func VerifyToken(tokenString string, claims jwt.MapClaims, secret string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
}

// AuthorizeAndGetClaims authorizes a context and returns the claims in its token
func AuthorizeAndGetClaims(c *gin.Context, secret string) (jwt.MapClaims, error) {
	tokenString := GetTokenFromHeader(c)
	claims := jwt.MapClaims{}
	if _, err := VerifyToken(tokenString, claims, secret); err != nil {
		return nil, fmt.Errorf("error getting token: %v", err)
	}
	return claims, nil
}
