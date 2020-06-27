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
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := &models.User{Status: "active"}

		if errs := s.decode(c, user); errs != nil {
			s.respond(c, "", http.StatusBadRequest, nil, errs)
			return
		}
		var err error
		user.Password, err = bcrypt.GenerateFromPassword([]byte(user.PasswordString), bcrypt.DefaultCost)
		if err != nil {
			//TODO i feel like sending back the error as is, isn't safe/neccessary
			//we can just log the original error and send back a custom error message
			log.Printf("hash password err: %v\n", err)
			s.respond(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}
		user, err = s.DB.CreateUser(user)
		if err != nil {
			log.Printf("create user err: %v\n", err)
			err, ok := err.(db.ValidationError)
			if ok {
				s.respond(c, "", http.StatusBadRequest, nil, []string{err.Error()})
				return
			}
			s.respond(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}
		s.respond(c, "signup successful", http.StatusCreated, nil, nil)
	}
}

func (s *Server) handleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := &models.User{}
		loginRequest := &struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}{}

		if errs := s.decode(c, loginRequest); errs != nil {
			s.respond(c, "", http.StatusBadRequest, nil, errs)
			return
		}
		// Check if the user with that username exists
		user, err := s.DB.FindUserByUsername(loginRequest.Username)
		if err != nil {
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				s.respond(c, "", http.StatusBadRequest, nil, []string{inactiveErr.Error()})
				return
			}
			log.Printf("No user: %v\n", err)
			s.respond(c, "", http.StatusUnauthorized, nil, []string{err.Error()})
			return
		}
		log.Printf("%v\n%s\n", user.Password, string(user.Password)) //TODO can we take this line away
		err = bcrypt.CompareHashAndPassword(user.Password, []byte(loginRequest.Password))
		if err != nil {
			log.Printf("passwords do not match %v\n", err)
			s.respond(c, "", http.StatusUnauthorized, nil, []string{err.Error()})
			return
		}

		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_email": user.Email})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

		if err != nil {
			log.Printf("token signing err %v\n", err)
			s.respond(c, "", http.StatusUnauthorized, nil, []string{err.Error()})
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
		s.respond(c, "login successful", http.StatusOK, gin.H{"user": user, "token": tokenString}, nil)
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
							s.respond(c, "logout failed", http.StatusInternalServerError, nil, []string{err.Error()})
							return
						}
						s.respond(c, "logout successful", http.StatusOK, nil, nil)
						return
					}
				}
			}
		}
		log.Printf("can't get info from context\n")
		s.respond(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
		return
	}
}

// handleShowProfile returns user's details
func (s *Server) handleShowProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				s.respond(c, "user details retrieved correctly", http.StatusOK, gin.H{
					"email":      user.Email,
					"phone":      user.Phone,
					"first_name": user.FirstName,
					"last_name":  user.LastName,
					"image":      user.Image,
					"username":   user.Username,
				}, nil)
				return
			}
		}
		log.Printf("can't get user from context\n")
		s.respond(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
	}
}

func (s *Server) handleUpdateUserDetails() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {

				username, email := user.Username, user.Email
				if errs := s.decode(c, user); errs != nil {
					s.respond(c, "", http.StatusBadRequest, nil, errs)
					return
				}

				//TODO try to eliminate this
				user.Username, user.Email = username, email
				user.UpdatedAt = time.Now()
				if err := s.DB.UpdateUser(user); err != nil {
					log.Printf("update user error : %v\n", err)
					s.respond(c, "", http.StatusInternalServerError, nil, []string{err.Error()})
					return
				}
				s.respond(c, "user updated successfuly", http.StatusOK, nil, nil)
				return
			}
		}

		log.Printf("can't get user from context\n")
		s.respond(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
	}
}

func (s *Server) handleGetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				users, err := s.DB.FindAllUsersExcept(user.Email)
				if err != nil {
					log.Printf("find users error : %v\n", err)
					s.respond(c, "", http.StatusInternalServerError, nil, []string{"could not find users"})
					return
				}
				s.respond(c, "retrieved users sucessfully", http.StatusOK, gin.H{"users": users}, nil)
				return
			}
		}
		s.respond(c, "", http.StatusUnauthorized, nil, []string{"unauthorized"})
		return
	}
}

func (s *Server) handleGetUserByUsername() gin.HandlerFunc {
	return func(c *gin.Context) {
		name := &struct {
			Username string `json:"username,omitempty" binding:"required"`
		}{}

		if errs := s.decode(c, name); errs != nil {
			s.respond(c, "", http.StatusBadRequest, nil, errs)
			return
		}

		user, err := s.DB.FindUserByUsername(name.Username)
		if err != nil {
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				s.respond(c, "", http.StatusBadRequest, nil, []string{inactiveErr.Error()})
				return
			}
			log.Printf("find user error : %v\n", err)
			s.respond(c, "user not found", http.StatusNotFound, nil, []string{err.Error()})
			return
		}

		s.respond(c, "user retrieved successfully", http.StatusOK, gin.H{
			"email":      user.Email,
			"phone":      user.Phone,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"image":      user.Image,
			"username":   user.Username,
		}, nil)
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
