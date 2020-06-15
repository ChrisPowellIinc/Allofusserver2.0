package models

import "time"

// User holds a user details
type User struct {
	FirstName      string    `json:"first_name" bson:"first_name,omitempty" binding:"required" form:"first_name"`
	LastName       string    `json:"last_name" bson:"last_name,omitempty" binding:"required" form:"last_name"`
	Phone          string    `json:"phone,omitempty" bson:"phone,omitempty" binding:"required" form:"phone"`
	Email          string    `json:"email" bson:"email,omitempty" binding:"required,email" form:"email"`
	Username       string    `json:"username" bson:"username,omitempty" binding:"required" form:"username"`
	Password       []byte    `json:"-" bson:"password,omitempty"`
	PasswordString string    `json:"password,omitempty" bson:"-" binding:"required" form:"password"`
	Reset          string    `json:"-" bson:"reset"`
	Image          string    `json:"image,omitempty" bson:"image,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	AccessToken    string    `json:"token,omitempty" bson:"token,omitempty"`
	// stripe payment details
	SessionID       string `json:"session_id,omitempty" bson:"session_id,omitempty"`
	SetupIntentID   string `json:"setup_intent_id,omitempty" bson:"setup_intent_id,omitempty"`
	PaymentMethodID string `json:"payment_method_id,omitempty" bson:"payment_method_id,omitempty"`
	CustomerID      string `json:"customer_id,omitempty" bson:"customer_id,omitempty"`
}
