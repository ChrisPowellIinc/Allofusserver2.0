package middleware

import (
	"log"
	"net/http"
	"os"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/server/errors"
	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/gin-gonic/gin"
)

// Authorize authorizes a request
func Authorize(findUserByEmail func(string) (*models.User, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, token, err := services.AuthorizeGetClaimsAndToken(c, os.Getenv("JWT_SECRET"))
		if err != nil {
			log.Printf("authorize claims error: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		user := &models.User{}
		if email, ok := claims["user_email"].(string); ok {
			if user, err = findUserByEmail(email); err != nil {
				if inactiveErr, ok := err.(errors.InActiveUserError); ok {
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

		// set the claims and user as context parameters.
		// so that the actions can use the claims from jwt token or the user
		c.Set("user", user)
		c.Set("claims", claims) //TODO remove this?...we dont use it
		c.Set("token", token)
		// calling next handler
		c.Next()
	}
}
