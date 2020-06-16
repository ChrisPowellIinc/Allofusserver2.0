package db

import (
	"fmt"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
)

// DB provides access to the different db
type DB interface {
	CreateUser(user models.User) (models.User, error)
	FindUserByUsername(username string) (models.User, error)
}

// ValidationError defines error that occur due to validation
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (v ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}
