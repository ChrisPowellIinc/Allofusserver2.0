package server

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/ChrisPowellIinc/Allofusserver2.0/servererrors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	validator "github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := &models.User{}

		if err := c.ShouldBindJSON(user); err != nil {
			errs := []string{}
			verr, ok := err.(validator.ValidationErrors)
			if ok {
				for _, fieldErr := range verr {
					errs = append(errs, servererrors.NewFieldError(fieldErr).String())
				}
			} else {
				errs = append(errs, "internal server error")
			}
			s.respond(c, "", http.StatusBadRequest, nil, errs)
			// c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
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
		user := &models.User{}
		type Login struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		var loginRequest Login
		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			errs := []string{}
			if err, ok := err.(validator.ValidationErrors); ok {
				for _, fieldErr := range err {
					errs = append(errs, servererrors.NewFieldError(fieldErr).String())
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
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				c.JSON(http.StatusBadRequest, gin.H{"errors": []string{inactiveErr.Error()}})
				return
			}
			log.Printf("No user: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			return
		}
		log.Printf("%v\n%s\n", user.Password, string(user.Password))
		err = bcrypt.CompareHashAndPassword(user.Password, []byte(loginRequest.Password))
		if err != nil {
			log.Printf("passwords do not match %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"username or password incorrect"}})
			return
		}

		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_email": user.Email})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

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
					if token, ok := tokenI.(string); ok {
						blacklist := &models.Blacklist{}
						blacklist.Email = user.Email
						blacklist.CreatedAt = time.Now()
						blacklist.Token = token

						err := s.DB.AddToBlackList(blacklist)
						if err != nil {
							log.Printf("can't add token to blacklist: %v\n", err)
							c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
							return
						}
						c.JSON(http.StatusOK, gin.H{"message": "logout sucessful"})
						return
					}
				}
			}
		}
		log.Printf("can't get info from context\n")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
}

// handleShowProfile returns user's details
func (s *Server) handleShowProfile() gin.HandlerFunc {
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

func (s *Server) handleUpdateUserDetails() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				username, email := user.Username, user.Email
				if err := c.ShouldBindJSON(user); err != nil {
					errs := []string{}
					for _, fieldErr := range err.(validator.ValidationErrors) {
						errs = append(errs, servererrors.NewFieldError(fieldErr).String())
					}
					c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
					return
				}
				user.Username, user.Email = username, email
				user.UpdatedAt = time.Now()
				if err := s.DB.UpdateUser(user); err != nil {
					log.Printf("update user error : %v\n", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "user updated successfuly"})
				return
			}
		}

		log.Printf("can't get user from context\n")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func (s *Server) handleGetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				users, err := s.DB.FindAllUsersExcept(user.Email)
				if err != nil {
					log.Printf("find users error : %v\n", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "could not find users"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"data": users, "message": "retrieved users sucessfully"})
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
}

func (s *Server) handleGetUserByUsername() gin.HandlerFunc {
	return func(c *gin.Context) {
		name := &struct {
			Username string `json:"username,omitempty" binding:"required"`
		}{}
		if err := c.ShouldBindJSON(name); err != nil {
			errs := []string{}
			for _, fieldErr := range err.(validator.ValidationErrors) {
				errs = append(errs, servererrors.NewFieldError(fieldErr).String())
			}
			c.JSON(http.StatusBadRequest, gin.H{"errors": errs})
			return
		}

		user, err := s.DB.FindUserByUsername(name.Username)
		if err != nil {
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": inactiveErr.Error()})
				return
			}
			log.Printf("find user error : %v\n", err)
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		// {
		// message:
		// 	data
		// 	status
		// 	errors
		// }

		c.JSON(http.StatusOK, gin.H{
			"message": "user retrieved successfully",
			"data": map[string]interface{}{
				"email":      user.Email,
				"phone":      user.Phone,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
				"image":      user.Image,
				"username":   user.Username,
			}})
		return
	}
}

/*
func uploadFileToS3(file multipart.File, fileName string, size int64, con *config.Config) error {
	// get the file size and read
	// the file content into a buffer
	buffer := make([]byte, size)
	file.Read(buffer)

	// config settings: this is where you choose the bucket,
	// filename, content-type and storage class of the file
	// you're uploading
	_, err := s3.New(con.AwsSession).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(con.Constants.S3Bucket),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("public-read"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(int64(size)),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
		StorageClass:         aws.String("INTELLIGENT_TIERING"),
	})
	return err
}

// UploadProfilePic uploads a user's profile picture
func (handler *Handler) UploadProfilePic(w http.ResponseWriter, r *http.Request) {
	userEmail, err := jwt.GetLoggedInUserEmail(r.Context())
	if err != nil {
		log.Println(err)
		models.HandleResponse(w, r, "Unable to retrieve authenticated user.", http.StatusUnauthorized, nil)
		return
	}

	maxSize := int64(2048000) // allow only 2MB of file size

	err = r.ParseMultipartForm(maxSize)
	if err != nil {
		log.Println(err)
		models.HandleResponse(w, r, "Image too large", http.StatusBadRequest, nil)
		return
	}

	file, fileHeader, err := r.FormFile("profile_picture")
	if err != nil {
		log.Println(err)
		models.HandleResponse(w, r, "Image not supplied", http.StatusBadRequest, nil)
		return
	}
	defer file.Close()

	// TODO:: Check for file type...
	supportedFileTypes := map[string]bool{
		".png":  true,
		".jpeg": true,
		".jpg":  true,
	}
	filetype := filepath.Ext(fileHeader.Filename)
	if !supportedFileTypes[filetype] {
		log.Println(filetype)
		models.HandleResponse(w, r, "This image file type is not supported", http.StatusBadRequest, nil)
		return
	}
	tempFileName := "profile_pics/" + bson.NewObjectId().Hex() + filetype
	err = uploadFileToS3(file, tempFileName, fileHeader.Size, handler.config)
	if err != nil {
		log.Println(err)
		models.HandleResponse(w, r, "An Error occured while uploading the image", http.StatusInternalServerError, nil)
		return
	}

	imageURL := "https://s3.us-east-2.amazonaws.com/www.all-of.us/" + tempFileName

	err = handler.config.DB.C("user").Update(bson.M{"email": userEmail}, bson.M{"$set": bson.M{"image": imageURL}})
	if err != nil {
		log.Println(err)
		models.HandleResponse(w, r, "Unable to update user's email.", http.StatusInternalServerError, nil)
		return
	}

	res := models.Response{}
	res.Message = "Successfully Created File"
	res.Status = http.StatusOK
	res.Data = map[string]interface{}{
		"imageurl": imageURL,
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, res)
}
*/
