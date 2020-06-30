package middleware

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/server/response"
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
		if err != nil && err.Error() != "Token is expired" {
			log.Printf("authorize access token error: %s\n", err.Error())
			respondAndAbort(c, "", http.StatusUnauthorized, nil, []string{"unauthorized"})
			return
		}

		if tokenInBlacklist(&accesstoken.Raw) {
			rt := &struct {
				RefreshToken string `json:"refresh_token,omitempty" binding:"required"`
			}{}

			if err := c.ShouldBindJSON(rt); err != nil {
				log.Printf("no refresh token in request body: %v\n", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized"})
				c.Abort()
				return
			}

			_, rtClaims, err := services.AuthorizeToken(&rt.RefreshToken, &secret)
			if err != nil {
				log.Printf("authorize refresh token error: %v\n", err)
				respondAndAbort(c, "", http.StatusUnauthorized, nil, []string{"refresh token is invalid"})
				return
			}

			if sub, ok := rtClaims["sub"].(int); ok && sub != 1 {
				log.Printf("invalid refresh token, the sub claim isn't correct")
				respondAndAbort(c, "", http.StatusUnauthorized, nil, []string{"refresh token is invalid"})
				return
			}

			//generate a new access token, and rest its exp time
			accessClaims["exp"] = time.Now().Add(services.AccessTokenValidity).Unix()
			newAccessToken, err := services.GenerateToken(jwt.SigningMethodHS256, accessClaims, &secret)
			if err != nil {
				log.Printf("can't generate new access token: %v\n", err)
				respondAndAbort(c, "", http.StatusUnauthorized, nil, []string{"can't generate new access token"})
				return
			}
			respondAndAbort(c, "new access token generated", http.StatusOK, gin.H{"access_token": *newAccessToken}, []string{"access token is invalid"})
			return
		}

		user := &models.User{}
		if email, ok := accessClaims["user_email"].(string); ok {
			if user, err = findUserByEmail(email); err != nil {
				if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
					respondAndAbort(c, "", http.StatusBadRequest, nil, []string{inactiveErr.Error()})
					return
				}
				log.Printf("find user by email error: %v\n", err)
				respondAndAbort(c, "", http.StatusNotFound, nil, []string{"user not found"})
				return
			}
		} else {
			log.Printf("user email is not string\n")
			respondAndAbort(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}

		// set the user and token as context parameters.
		c.Set("user", user)
		c.Set("access_token", accesstoken.Raw)
		// calling next handler
		c.Next()
	}
}

// respondAndAbort calls response.JSON
//and aborts the Context
func respondAndAbort(c *gin.Context, message string, status int, data interface{}, errs []string) {
	response.JSON(c, message, status, data, errs)
	c.Abort()
}
