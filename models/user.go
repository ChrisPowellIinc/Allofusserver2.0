package models

// User holds a user details
type User struct {
	ID        uint64 `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	SessionID int    `json:"session_id"`
}
