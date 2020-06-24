package models

import "time"

//Blacklist helps us blacklist tokens
type Blacklist struct {
	Email     string    `json:"email,omitempty" bson:"token,omitempty" binding:"required"`
	Token     string    `json:"token,omitempty" bson:"token,omitempty" binding:"required"`
	CreatedAt time.Time `json:"created_at,omitempty" bson:"token,omitempty" binding:"required"`
}
