package websocket

import (
	

	"log"
	"net/http"
	"strings"
	"time"

	"bytes"
	"poc/task/auth"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	
)

var (
	rooms = make(map[string]*Room)
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
	conn          *websocket.Conn // WebSocket connection
	send          chan []byte     // Channel for sending messages to the client
	mobile_number string          // Mobile number associated with the client
}

type Room struct {
	clients   map[*Client]bool
	broadcast chan []byte
}

func NewRoom() *Room {
	return &Room{
		clients:   make(map[*Client]bool),
		broadcast: make(chan []byte),
	}
}

func (r *Room) Start() {
	for {
		select {
		case message := <-r.broadcast:
			for client := range r.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(r.clients, client)
				}
			}
		}
	}
}

func (r *Room) Join(client *Client) {
	r.clients[client] = true
}

func getRoomName(mobileNumber1 string, mobileNumber2 string) string {
	if mobileNumber1 < mobileNumber2 {
		return mobileNumber1 + "-" + mobileNumber2
	} else {
		return mobileNumber2 + "-" + mobileNumber1
	}
}

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
	mobileNumber1, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
	if !ok {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Get the receiver_number parameter from the URL
	vars := mux.Vars(r)
	mobileNumber2, ok := vars["receiver_number"]
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

	// Create a new client and add it to the list of clients in the room
	client := &Client{conn: conn, send: make(chan []byte, 256), mobile_number: mobileNumber1}
	roomName := getRoomName(mobileNumber1, mobileNumber2)
	room, ok := rooms[roomName]
	if !ok {
		room = NewRoom()
		rooms[roomName] = room
		go room.Start()
	}
	room.Join(client)

	// Start a goroutine to read incoming messages from the client
	go func() {
		defer func() {
			client.conn.Close()
			room.broadcast <- []byte(client.mobile_number + " left the chat")
			delete(room.clients, client)
			if len(room.clients) == 0 {
				delete(rooms, roomName)
			}
		}()

		room.broadcast <- []byte(client.mobile_number + " joined the chat")

		for {
			_, message, err := client.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("error: %v", err)
				}
				break
			}
			message = bytes.TrimSpace(message)
			if len(message) == 0 {
				continue
			}
			room.broadcast <- []byte(client.mobile_number + ": " + string(message))
		}
	}()

	// Start a goroutine to write outgoing messages to the client
	go func() {
		defer func() {
			client.conn.Close()
		}()

		for {
			select {
			case message, ok := <-client.send:
				if !ok {
					client.conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}
				err := client.conn.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					return
				}
			}
		}
	}()
}

func StartRoom(room *Room) {
	for {
		select {
		case message := <-room.broadcast:
			for client := range room.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(room.clients, client)
				}
			}
		}
	}
}
