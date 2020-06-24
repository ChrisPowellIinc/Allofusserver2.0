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
	Status         string    `json:"status,omitempty"` //TODO should this have the "-" tag?
	CreatedAt      time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
	AccessToken    string    `json:"token,omitempty" bson:"token,omitempty"`
	// stripe payment details
	SessionID       string `json:"session_id,omitempty" bson:"session_id,omitempty"`
	SetupIntentID   string `json:"setup_intent_id,omitempty" bson:"setup_intent_id,omitempty"`
	PaymentMethodID string `json:"payment_method_id,omitempty" bson:"payment_method_id,omitempty"`
	CustomerID      string `json:"customer_id,omitempty" bson:"customer_id,omitempty"`
}

// FIRST
// Add Status field to the user's model (Status string `json:"status"`)
// Add updated_at field

// 1.
// create a blacklist collection (MongoDB)
// add the token to blacklist
// create middleware that would check that there is token in the request header (Authorization: Bearer token)
// verify the token.
// make sure you check the db for the email and make sure the status is active.
//TODO but we dont check the status tho?

// type blacklist struct {email string, token: string, created_at, time.Time}
// Logout method: get the token and save it in the blacklist collection.

//
//
// Profile page where user details would be shown and updated.
// Timeline page: list all the users, and get each user details
// User details page: show details of a user

// 2.
// Endpoint for returning loggedin user details
// 3.
// Update user detail (DO NOT UPDATE: username, email, password, status)
// update the updated_at field of the user model to time.Now()
// 4.
// endpoint to list all users
// 5.
// get a user details based on the username passed to it.
