package websocket

import (
	// "encoding/json"
	"unicode"

	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"bufio"
	"os"
	"poc/task/auth"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	// "golang.org/x/text/message"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	Subprotocols:    []string{"13"},
	CheckOrigin: func(r *http.Request) bool {
		return true
	},

	HandshakeTimeout:  500 * time.Second,
	EnableCompression: false,
	Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		log.Println("WebSocket error:", reason)
		http.Error(w, "Internal server error", status)
	},
}

type Client struct {
	conn          *websocket.Conn
	send          chan []byte
	mobile_number string
}

var (
	clients   = make(map[*Client]bool)
	broadcast = make(chan []byte)
)

func HandleWebsocket(w http.ResponseWriter, r *http.Request) {
	// Parse and validate the JWT token...
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) < 7 || strings.ToLower(tokenString[:7]) != "bearer " {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	tokenString = tokenString[7:]
	token, err := auth.ParseToken(tokenString)
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	mobileNumber, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
	if !ok {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Get the receiver_number parameter from the URL
	vars := mux.Vars(r)
	receiverNumber, ok := vars["receiver_number"]
	if !ok {
		http.Error(w, "Missing receiver_number parameter", http.StatusBadRequest)
		return
	}

	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
		return
	}

	// Create a new client and add it to the list of clients
	client := &Client{conn: conn, send: make(chan []byte, 256), mobile_number: mobileNumber}
	clients[client] = true

	// Start a goroutine to read incoming messages from the client
	go func() {
		defer func() {
			client.conn.Close()
			delete(clients, client)
		}()

		for {
			_, message, err := client.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
					log.Printf("WebSocket error: %v\n", err)
				}
				break
			}

			// Check if the message is intended for a specific client
			if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
				receiver := string(message[1:])
				if receiver != receiverNumber {
					continue
				}
				for c := range clients {
					if c.mobile_number == receiver {
						c.send <- message[2:]
						break
					}
				}
			} else {
				// Broadcast the message to all clients
				broadcast <- message
			}
		}
	}()

	// Start a goroutine to write outgoing messages to the client
	go func() {
		defer func() {
			client.conn.Close()
			delete(clients, client)
		}()
		for {
			select {
			case message, ok := <-client.send:
				if !ok {
					return
				}
				err := client.conn.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					log.Printf("Error writing message to connection: %v\n", err)
					return
				}
			case message := <-broadcast:
				err := client.conn.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					log.Printf("Error writing message to connection: %v\n", err)
					return
				}
			}
		}
	}()

	// Send and receive messages via wscat
	go func() {
		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter message: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if len(message) > 0 {
				err := conn.WriteMessage(websocket.TextMessage, []byte(message))
				// Add authentication header to the message
				authHeader := http.Header{}
				authHeader.Set("Authorization", "Bearer "+tokenString)

				err = conn.WriteMessage(websocket.TextMessage, []byte(message))
				if err != nil {
					log.Printf("Error writing message to connection: %v\n", err)
					return
				}

				// Read incoming messages from the server
				_, serverMessage, err := conn.ReadMessage()
				if err != nil {
					log.Printf("Error reading message from connection: %v\n", err)
					return
				}

				log.Printf("Received message from server: %s\n", serverMessage)
			}
		}
	}()
}

func BroadcastMessages() {
	fmt.Println("at-14.")
	for {
		fmt.Println("at-15.")
		message := <-broadcast
		for client := range clients {
			fmt.Println("at-16.")
			select {
			case client.send <- message:
			default:
				close(client.send)
				delete(clients, client)
			}
			fmt.Println("at-17.")
		}
		fmt.Println("at-18.")
	}
}

