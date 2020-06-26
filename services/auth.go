package services

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// GetTokenFromHeader returns the token string in the authorization header
func GetTokenFromHeader(c *gin.Context) string {
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader != "" && len(authHeader) > 8 {
		return authHeader[7:]
	}
	return ""
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

// AuthorizeGetClaimsAndToken authorizes a context and returns the claims in its token
func AuthorizeGetClaimsAndToken(c *gin.Context, secret string) (jwt.MapClaims, *jwt.Token, error) {
	if tokenString := GetTokenFromHeader(c); tokenString != "" {
		claims := jwt.MapClaims{}
		token, err := VerifyToken(tokenString, claims, secret)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting token: %v", err)
		}
		return claims, token, nil
	}
	return nil, nil, fmt.Errorf("token invalid")
}
