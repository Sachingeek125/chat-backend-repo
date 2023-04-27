package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	// "github.com/gorilla/websocket"
	"poc/task/handlers"
	"poc/task/websocket"
	// "path/filepath"
	// "context"
	// "cloud.google.com/go/storage"
	// "github.com/gorilla/mux"
	// "google.golang.org/api/option"
)

// var upgrader = websocket.Upgrader{
// 	ReadBufferSize:  1024,
// 	WriteBufferSize: 1024,
// }

func main() {
	log.Printf("Server Started on:%d", 8080)

	fmt.Println()
	r := mux.NewRouter()
	r.HandleFunc("/register", handlers.HandleRegistration).Methods("POST")
	r.HandleFunc("/login", handlers.HandleLogin).Methods("POST")
	r.HandleFunc("/send", handlers.HandleSendMessage).Methods("POST")
	r.HandleFunc("/inbox", handlers.HandleGetInbox).Methods("GET")
	r.HandleFunc("/outbox", handlers.HandleGetOutbox).Methods("GET")
	r.HandleFunc("/ws/{receiver_number}", websocket.HandleWebsocket).Methods("GET")
	r.HandleFunc("/send/document/{receiver_number}", handlers.HandleSendDocument).Methods("POST")
	r.HandleFunc("/inboxDocument", handlers.HandleGetInboxDocuments).Methods("GET")
	r.HandleFunc("/outboxDocument", handlers.HandleOutboxDocuments).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
	go websocket.BroadcastMessages()
}
