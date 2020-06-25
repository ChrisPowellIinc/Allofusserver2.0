package middleware

import (
	"log"
	"net/http"
	"os"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/gin-gonic/gin"
)

// Authorize authorizes a request
func Authorize(findUserByEmail func(string) (*models.User, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, token, err := services.AuthorizeGetClaimsAndToken(c, os.Getenv("JWTSecret"))
		if err != nil {
			log.Printf("%v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		var user *models.User
		if email, ok := claims["user_email"].(string); ok {
			if user, err = findUserByEmail(email); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err})
				return
			}
		} else {
			log.Printf("user email is not string\n")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		if user.Status != "active" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not activated"})
			return
		}

		// set the claims and user as context parameters.
		// so that the actions can use the claims from jwt token or the user
		c.Set("user", user)
		c.Set("claims", claims) //TODO remove this?...we dont use it
		c.Set("token", token)
		// calling next handler
		c.Next()
	}
}
