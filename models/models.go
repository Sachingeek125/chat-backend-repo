package models

import "github.com/google/uuid"

// define the user struct
type User struct {
	// ID        uuid.UUID `json:"id"`
	MobileNumber string `json:"mobile_number"`
	Password     string `json:"password"`
	Bio          string `json:"bio"`
}

type LoginReq struct {
	// ID        uuid.UUID `json:"id"`
	MobileNumber string `json:"mobile_number"`
	Password     string `json:"password"`
}

type Message struct {
	ID        int64  `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

type Document struct {
	ID          uuid.UUID `json:"id"`
	Sender      string    `json:"sender"`
	Receipent   string    `json:"receipent"`
	DocumentURL string    `json:"document_url"`
	Timestamp   string    `json:"timeStamp"`
}
