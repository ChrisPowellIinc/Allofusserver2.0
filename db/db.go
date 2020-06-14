package db

import "github.com/spankie/aou/models"

// Users holds a list of all users identified by thier IDs
type Users []models.User

// DB provides access to the different db
type DB struct {
	Users Users
}
