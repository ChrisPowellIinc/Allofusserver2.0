package middleware

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/servererrors"
	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Authorize authorizes a request
func Authorize(findUserByEmail func(string) (*models.User, error), tokenInBlacklist func(*string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := os.Getenv("JWT_SECRET")
		accToken := services.GetTokenFromHeader(c)
		accesstoken, accessClaims, err := services.AuthorizeToken(&accToken, &secret)
		if err != nil {
			log.Printf("authorize access token error: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if tokenInBlacklist(&accesstoken.Raw) || isTokenExpired(accesstoken) {
			rt := &struct {
				RefreshToken string `json:"refresh_token,omitempty" binding:"required"`
			}{}

			if err := c.ShouldBindJSON(rt); err != nil {
				log.Printf("no refresh token in request body: %v\n", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			refreshToken, rtClaims, err := services.AuthorizeToken(&rt.RefreshToken, &secret)
			if err != nil {
				log.Printf("authorize refresh token error: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token is invalid"})
				c.Abort()
				return
			}

			if sub, ok := rtClaims["sub"].(int); ok && sub != 1 {
				log.Printf("invalid refresh token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token is invalid"})
				c.Abort()
				return
			}

			if !isTokenExpired(refreshToken) {
				accessClaims["exp"] = time.Now().Add(time.Minute * 20).Unix()
				newAccessToken, err := services.GenerateToken(jwt.SigningMethodHS256, accessClaims, &secret)
				if err != nil {
					log.Printf("generate new access token error: %v\n", err)
					c.JSON(http.StatusUnauthorized, gin.H{"error": "can't generate new access token"})
					c.Abort()
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "new access token generated", "access_token": *newAccessToken})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "access and refresh token expired"})
			c.Redirect(http.StatusUnauthorized, "/api/v1/auth/login") //TODO testing
			c.Abort()
			return
		}

		//check if token is expired...
		//if token is expired check the refresh token is expired
		//if refresh aint expired, the regen new access token and send back to client
		//but ABORT the request
		//

		user := &models.User{}
		if email, ok := accessClaims["user_email"].(string); ok {
			if user, err = findUserByEmail(email); err != nil {
				if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
					c.JSON(http.StatusBadRequest, gin.H{"error": inactiveErr.Error()})
					c.Abort()
					return
				}
				log.Printf("find user by email error: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}
		} else {
			log.Printf("user email is not string\n")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			c.Abort()
			return
		}

		// set the user and token as context parameters.
		c.Set("user", user)
		c.Set("access_token", accesstoken.Raw)
		// calling next handler
		c.Next()
	}
}

func isTokenExpired(token *jwt.Token) bool {
	if exp, ok := token.Claims.(jwt.MapClaims)["exp"].(int64); ok {
		return time.Now().Unix() > exp
	}
	return false
}
