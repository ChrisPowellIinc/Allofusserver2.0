package server

import (
	"log"
	"net/http"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"golang.org/x/crypto/bcrypt"
)

// TODO: use env variables to store secret
const JWTSecret = "JWTSecret"

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		if err := c.ShouldBindJSON(&user); err != nil {
			errs := []string{}
			for _, fieldErr := range err.(validator.ValidationErrors) {
				errs = append(errs, fieldError{fieldErr}.String())
			}
			c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
			return
		}
		var err error
		user.Password, err = bcrypt.GenerateFromPassword([]byte(user.PasswordString), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("hash password err: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Sorry a problem occured, please try again",
				"status":  http.StatusInternalServerError,
			})
			return
		}
		user, err = s.DB.CreateUser(user)
		if err != nil {
			log.Printf("create user err: %v\n", err)
			err, ok := err.(db.ValidationError)
			if ok {
				c.JSON(http.StatusInternalServerError, gin.H{
					"errors": []string{err.Error()},
					"Status": http.StatusBadRequest,
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Sorry a problem occured, please try again",
				"Status":  http.StatusInternalServerError,
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "signup successful",
		})
	}
}

func (s *Server) handleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		type Login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var loginRequest Login
		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			errs := []string{}
			if err, ok := err.(validator.ValidationErrors); ok {
				for _, fieldErr := range err {
					errs = append(errs, fieldError{fieldErr}.String())
				}
				c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			}
			return
		}
		// Check if the user with that username exists
		user, err := s.DB.FindUserByUsername(loginRequest.Username)
		if err != nil {
			log.Printf("No user: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password))
		if err != nil {
			log.Printf("Passwords do not match %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			return
		}

		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_email": user.Email})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(JWTSecret))

		// _, token, err := jwt.TokenAuth.Encode(jwtauth.Claims{"user_email": user.Email})

		if err != nil {
			log.Printf("token signing err %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			return
		}

		// Data: map[string]interface{}{
		// 	"token":      tokenString,
		// 	"first_name": user.FirstName,
		// 	"last_name":  user.LastName,
		// 	"phone":      user.Phone,
		// 	"email":      user.Email,
		// 	"username":   user.Username,
		// 	"image":      user.Image,
		// },

		//change user status to active
		user.Status = "active"
		c.JSON(http.StatusOK, gin.H{
			"message": "login successful",
			"data": map[string]interface{}{
				"user":  user,
				"token": tokenString,
			},
		})
	}
}

func (s *Server) handleLogout() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Request.Header.Get("Authorization")
		claims := jwt.MapClaims{}
		token, err := services.VerifyToken(tokenString, claims, JWTSecret)
		if err != nil {
			log.Printf("error getting token: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"}) //TODO make this meaningful
			return
		}

		if email, ok := claims["user_email"].(string); ok {
			_, err := s.DB.FindUserByEmail(email)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err})
				return
			}
			// if user.Status != "active" {
			// 	c.JSON(http.StatusForbidden, gin.H{"errors": "user already logged out"})
			// 	return
			// }
			// user.Status = "inactive"
			var blacklist models.Blacklist
			blacklist.Email = email
			blacklist.CreatedAt = time.Now()
			blacklist.Token = token.Raw
			if err = s.DB.PutInBlackList(blacklist); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"logout failed": err})
				return
			}
		} else {
			log.Printf("user email is not string\n")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
	}
}
