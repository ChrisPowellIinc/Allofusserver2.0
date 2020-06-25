package server

import (
	"log"
	"net/http"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"golang.org/x/crypto/bcrypt"
)

// TODO: use env file to store secret
const JWTSecret = "JWTSecret"

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user *models.User

		if err := c.ShouldBindJSON(user); err != nil {
			errs := []string{}
			for _, fieldErr := range err.(validator.ValidationErrors) {
				errs = append(errs, fieldError{fieldErr}.String())
				// c.JSON(http.StatusBadRequest, fieldError{fieldErr}.String())
				// return // exit on first error
			}
			c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
			return
		}
		var err error
		user.Password, err = bcrypt.GenerateFromPassword([]byte(user.PasswordString), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Sorry a problem occured, please try again",
				"status":  http.StatusInternalServerError,
			})
			return
		}
		user, err = s.DB.CreateUser(user)
		if err != nil {
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
		var user *models.User
		type Login struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
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
		//TODO why do you []byte user.Password?...its already a []byte
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

		if tokenI, exists := c.Get("token"); exists {
			if userI, exists := c.Get("user"); exists {
				if user, ok := userI.(*models.User); ok {
					if token, ok := tokenI.(*jwt.Token); ok {
						blacklist := &models.Blacklist{}
						blacklist.Email = user.Email
						blacklist.CreatedAt = time.Now()
						blacklist.Token = token.Raw

						if err := s.DB.AddToBlackList(blacklist); err != nil {
							c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
							return
						}
					}
				}
			}
		}
		log.Printf("can't get info from context\n")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
}
func (s *Server) showProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				c.JSON(http.StatusOK, gin.H{
					"email":      user.Email,
					"phone":      user.Phone,
					"first_name": user.FirstName,
					"last_name":  user.LastName,
					"image":      user.Image,
					"username":   user.Username,
				})
				return
			}
		}
		log.Printf("can't get user from context\n")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
