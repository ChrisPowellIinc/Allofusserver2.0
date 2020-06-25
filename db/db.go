package db

import "github.com/ChrisPowellIinc/Allofusserver2.0/models"

// DB provides access to the different db
type DB interface {
	CreateUser(user *models.User) (*models.User, error)
	FindUserByUsername(username string) (*models.User, error)
	FindUserByEmail(email string) (*models.User, error)
	AddToBlackList(blacklist *models.Blacklist) error //TODO might remove this?
}
