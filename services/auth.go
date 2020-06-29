package services

import (
	"fmt"
	"os"

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

// verifyAccessToken verifies a token
func verifyToken(tokenString *string, claims jwt.MapClaims, secret *string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(*tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(*secret), nil
	})
}

// AuthorizeAccessToken authorizes a context and returns the claims in its token
func AuthorizeAccessToken(c *gin.Context, secret *string) (*jwt.Token, jwt.MapClaims, error) {
	if tokenString := GetTokenFromHeader(c); tokenString != "" {
		claims := jwt.MapClaims{}
		token, err := verifyToken(&tokenString, claims, secret)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting token: %v", err)
		}
		return token, claims, nil
	}
	return nil, nil, fmt.Errorf("empty token")
}

// AuthorizeRefreshToken check if a refresh token is valid
func AuthorizeRefreshToken(refreshToken *string, secret *string) (*jwt.Token, jwt.MapClaims, error) {
	if refreshToken != nil || *refreshToken != "" {
		claims := jwt.MapClaims{}
		token, err := verifyToken(refreshToken, claims, secret)
		if err != nil {
			return nil, nil, err
		}
		return token, claims, nil
	}
	return nil, nil, fmt.Errorf("empty token")
}

// GenerateAccessAndRefreshTokens generates new access and refresh tokens using
// acc_claims as the claims for the access token and refresh_claims for the
// refresh token
func GenerateAccessAndRefreshTokens(signMethod *jwt.SigningMethodHMAC, accessClaims jwt.MapClaims, refreshClaims jwt.MapClaims) (*string, *string, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))
	accToken := jwt.NewWithClaims(signMethod, accessClaims)

	// Sign and get the complete encoded token as a string using the secret
	accTokenString, err := accToken.SignedString(secret)
	if err != nil {
		return nil, nil, err
	}

	refreshToken := jwt.NewWithClaims(signMethod, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(secret)
	if err != nil {
		return nil, nil, err
	}
	return &accTokenString, &refreshTokenString, nil
}

// GenerateAccessToken generates only an access token
func GenerateAccessToken(claims jwt.MapClaims, secret *string) (*string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(*secret))
	if err != nil {
		return nil, fmt.Errorf("")
	}
	return &tokenString, nil
}
