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

func HandleWebsocketoo(w http.ResponseWriter, r *http.Request) {

	// Parse and validate the JWT token
	tokenString := r.Header.Get("Authorization")
	fmt.Printf("tokenstring: %s", tokenString)
	log.Printf("Token string: %s\n", tokenString)
	fmt.Println()
	if len(tokenString) < 7 || strings.ToLower(tokenString[:7]) != "bearer " {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Println("at-1.")
	tokenString = tokenString[7:]
	fmt.Println(tokenString)
	token, err := auth.ParseToken(tokenString)
	fmt.Println("at-2.")
	if err != nil {
		log.Printf("Error parsing token: %v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println("at-3.")
	if !token.Valid {
		log.Printf("Invalid token: %v\n", token)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Println("at-4.")
	mobileNumber, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
	if !ok {
		log.Println("Mobile number not found in token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Println("at-5.")
	log.Printf("Mobile number: %s\n", mobileNumber)

	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v\n", err)
		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
		return
	}

	// Create a new client and add it to the list of clients
	client := &Client{conn: conn, send: make(chan []byte, 256)}
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
				log.Printf("Read error: %v\n", err)
				if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived) {
					log.Printf("CloseError: %v\n", err)
				}
				if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) || websocket.IsCloseError(err, websocket.CloseNoStatusReceived) {
					log.Printf("CloseError 1006: %v\n", err)
				}
				break
			}
			if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
				receiver := string(message[1])
				for c := range clients {
					if c != client {
						if strings.TrimPrefix(c.conn.RemoteAddr().String(), "[::1]:") == receiver {
							c.send <- message[2:]
						}
					}
				}
				// } else {
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
			case <-time.After(time.Second * 30):
				err := client.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second*5))
				if err != nil {
					log.Printf("Error sending ping to client: %v\n", err)
					return
				}
			}
		}
	}()
}

// func HandleWebsocket(w http.ResponseWriter, r *http.Request) {
// 	// Parse and validate the JWT token...
// 	// (Same as in the original code)

// 	// Parse and validate the JWT token
// 	tokenString := r.Header.Get("Authorization")
// 	fmt.Printf("tokenstring: %s", tokenString)
// 	log.Printf("Token string: %s\n", tokenString)
// 	fmt.Println()
// 	if len(tokenString) < 7 || strings.ToLower(tokenString[:7]) != "bearer " {
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-1.")
// 	tokenString = tokenString[7:]
// 	fmt.Println(tokenString)
// 	token, err := auth.ParseToken(tokenString)
// 	fmt.Println("at-2.")
// 	if err != nil {
// 		log.Printf("Error parsing token: %v\n", err)
// 		http.Error(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-3.")
// 	if !token.Valid {
// 		log.Printf("Invalid token: %v\n", token)
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-4.")
// 	mobileNumber, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
// 	if !ok {
// 		log.Println("Mobile number not found in token")
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-5.")
// 	log.Printf("Mobile number: %s\n", mobileNumber)

// 	// Upgrade the HTTP connection to a WebSocket connection
// 	conn, err := upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		log.Printf("Failed to upgrade connection: %v\n", err)
// 		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
// 		return
// 	}
// 	defer conn.Close()

// 	// Create a new client and add it to the list of clients
// 	client := &Client{conn: conn, send: make(chan []byte, 256)}
// 	clients[client] = true

// 	// Start a goroutine to read incoming messages from the client
// 	go func() {
// 		defer func() {
// 			client.conn.Close()
// 			delete(clients, client)
// 		}()
// 		for {
// 			_, message, err := client.conn.ReadMessage()
// 			if err != nil {
// 				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
// 					log.Printf("WebSocket error: %v\n", err)
// 				}
// 				break
// 			}
// 			// Check if the message is intended for a specific client
// 			if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
// 				receiver := string(message[1])
// 				for c := range clients {
// 					if c != client {
// 						if r.Header.Get("X-User-Id") == receiver {
// 							c.send <- message[2:]
// 						}
// 					}
// 				}
// 			} else {
// 				// Broadcast the message to all clients
// 				broadcast <- message
// 			}
// 		}
// 	}()

// 	// Start a goroutine to write outgoing messages to the client
// 	go func() {
// 		defer client.conn.Close()
// 		for {
// 			select {
// 			case message, ok := <-client.send:
// 				if !ok {
// 					return
// 				}
// 				err := client.conn.WriteMessage(websocket.TextMessage, message)
// 				if err != nil {
// 					log.Printf("Error writing message to connection: %v\n", err)
// 					return
// 				}
// 			}
// 		}
// 	}()
// }

// func main() {
//     // Set up the HTTP server...
//     // (Same as in the original code)

//     // Start the broadcast goroutine
//     go broadcastMessages()

//     // Start the HTTP server
//     log.Fatal(http.ListenAndServe(":8080", nil))
// }

// func HandleWebsocket(w http.ResponseWriter, r *http.Request) {
// 	// Parse and validate the JWT token
// 	tokenString := r.Header.Get("Authorization")
// 	fmt.Printf("tokenstring: %s", tokenString)
// 	log.Printf("Token string: %s\n", tokenString)
// 	fmt.Println()
// 	if len(tokenString) < 7 || strings.ToLower(tokenString[:7]) != "bearer " {
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-1.")
// 	tokenString = tokenString[7:]
// 	fmt.Println(tokenString)
// 	token, err := auth.ParseToken(tokenString)
// 	fmt.Println("at-2.")
// 	if err != nil {
// 		log.Printf("Error parsing token: %v\n", err)
// 		http.Error(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-3.")
// 	if !token.Valid {
// 		log.Printf("Invalid token: %v\n", token)
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-4.")
// 	mobileNumber, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
// 	if !ok {
// 		log.Println("Mobile number not found in token")
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-5.")
// 	log.Printf("Mobile number: %s\n", mobileNumber)

// 	// Upgrade the HTTP connection to a WebSocket connection
// 	conn, err := upgrader.Upgrade(w, r, nil)
// 	fmt.Println("at-6.")
// 	if err != nil {
// 		log.Printf("Failed to upgrade connection: %v\n", err)
// 		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
// 		return
// 	}
// 	defer conn.Close()
// 	fmt.Println("at-7.")

// 	// Wait for WebSocket handshake to complete

// 	for {
// 		_, _, err := conn.ReadMessage()

// 		if err != nil {
// 			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
// 				log.Printf("WebSocket error: %v\n", err)
// 			}
// 			// Properly close the WebSocket connection before exiting
// 			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
// 			conn.Close()
// 			break
// 		}
// 		fmt.Println("at-8.")
// 		if websocket.IsWebSocketUpgrade(r) {

// 			break
// 		}
// 		fmt.Println("at-9.")
// 		time.Sleep(time.Millisecond * 20)
// 	}

// 	// Listen for incoming messages from the client
// 	for {
// 		_, message, err := conn.ReadMessage()
// 		fmt.Println("at-10.")
// 		if err != nil {
// 			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
// 				log.Printf("WebSocket error: %v\n", err)
// 			}
// 			fmt.Println("at-11.")
// 			break
// 		}

// 		// Send the message to the recipient
// 		var msg models.Message
// 		err = json.Unmarshal(message, &msg)
// 		fmt.Println("at-12.")
// 		if err != nil {
// 			log.Printf("Error unmarshalling message: %v\n", err)
// 			break

// 		}
// 		fmt.Println("at-13.")
// 		msg.From = mobileNumber
// 		id, err := db.GetNextMessageID()
// 		fmt.Println("at-14.")
// 		if err != nil {
// 			log.Printf("Error getting next message ID: %v\n", err)
// 			break
// 		}
// 		fmt.Println("at-15.")
// 		msg.ID = id
// 		err = db.AddMessageToRedis(msg)
// 		fmt.Println("at-16.")
// 		if err != nil {
// 			log.Printf("Error adding message to Redis: %v\n", err)
// 			break
// 		}
// 		fmt.Println("at-17.")
// 		err = conn.WriteMessage(websocket.TextMessage, []byte(strconv.FormatInt(msg.ID, 10)))
// 		fmt.Println("at-18.")
// 		if err != nil {
// 			log.Printf("Error writing message to connection: %v\n", err)
// 			break
// 		}
// 		fmt.Println("at-19.")
// 	}
// }

// if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
// 	receiver := string(message[1])
// 	if receiver == receiverNumber {
// 		for c := range clients {
// 			if c != client && c.mobile_number == receiverNumber {
// 				c.send <- message[2:]
// 			}
// 		}
// 	}
// } else {
// 	broadcast <- message
// }

// if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
// 	receiver := string(message[1])
// 	if receiver != receiverNumber {
// 		continue
// 	}
// 	for c := range clients {
// 		if c != client {
// 			if c.mobile_number == receiverNumber {
// 				c.send <- message[2:]
// 			}
// 		}
// 	}
// } else {
// 	// Broadcast the message to all clients
// 	broadcast <- message
// }

// func HandleWebsocket(w http.ResponseWriter, r *http.Request) {
// 	// Parse and validate the JWT token...
// 	// (Same as in the original code)
// 	tokenString := r.Header.Get("Authorization")
// 	fmt.Printf("tokenstring: %s", tokenString)
// 	log.Printf("Token string: %s\n", tokenString)
// 	fmt.Println()
// 	if len(tokenString) < 7 || strings.ToLower(tokenString[:7]) != "bearer " {
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-1.")
// 	tokenString = tokenString[7:]
// 	fmt.Println(tokenString)
// 	token, err := auth.ParseToken(tokenString)
// 	fmt.Println("at-2.")
// 	if err != nil {
// 		log.Printf("Error parsing token: %v\n", err)
// 		http.Error(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-3.")
// 	if !token.Valid {
// 		log.Printf("Invalid token: %v\n", token)
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-4.")
// 	mobileNumber, ok := token.Claims.(jwt.MapClaims)["mobile_number"].(string)
// 	if !ok {
// 		log.Println("Mobile number not found in token")
// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
// 		return
// 	}
// 	fmt.Println("at-5.")
// 	log.Printf("Mobile number: %s\n", mobileNumber)

// 	// Get the receiver_number parameter from the URL
// 	fmt.Println("at-1.")
// 	receiverNumber := mux.Vars(r)["receiver_number"]

// 	fmt.Println("at-2.")
// 	// Upgrade the HTTP connection to a WebSocket connection
// 	conn, err := upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		log.Printf("Failed to upgrade connection: %v\n", err)
// 		http.Error(w, "Failed to upgrade connection", http.StatusInternalServerError)
// 		return
// 	}
// 	fmt.Println("at-3.")

// 	// Create a new client and add it to the list of clients
// 	client := &Client{conn: conn, send: make(chan []byte, 256)}
// 	clients[client] = true
// 	fmt.Println("at-4.")
// 	// Start a goroutine to read incoming messages from the client
// 	go func() {
// 		defer func() {
// 			client.conn.Close()
// 			delete(clients, client)
// 		}()
// 		fmt.Println("at-5.")
// 		for {
// 			_, message, err := client.conn.ReadMessage()
// 			fmt.Println(string(message))
// 			fmt.Println("here:")
// 			if err != nil {
// 				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
// 					log.Printf("WebSocket error: %v\n", err)
// 				}
// 				log.Printf("Read error: %v\n", err)
// 				if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived) {
// 					log.Printf("CloseError: %v\n", err)
// 				}
// 				if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) || websocket.IsCloseError(err, websocket.CloseNoStatusReceived) {
// 					log.Printf("CloseError 1006: %v\n", err)
// 				}
// 				break
// 			}
// 			fmt.Println("at-6.")
// 			// Check if the message is intended for a specific client
// 			if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
// 				receiver := string(message[1])
// 				if receiver != receiverNumber {
// 					continue
// 				}
// 				fmt.Println("at-7.")
// 				for c := range clients {
// 					if c != client {
// 						if c.mobile_number == receiverNumber {
// 							c.send <- message[2:]
// 						}
// 						fmt.Println("at-8.")
// 					}
// 				}
// 			} else {
// 				// Broadcast the message to all clients
// 				broadcast <- message
// 			}
// 		}
// 		fmt.Println("at-9.")
// 	}()

// 	// Start a goroutine to write outgoing messages to the client
// 	go func() {
// 		defer func() {
// 			client.conn.Close()
// 			delete(clients, client)
// 		}()
// 		fmt.Println("at-10.")
// 		for {
// 			select {
// 			case message, ok := <-client.send:
// 				if !ok {
// 					return
// 				}
// 				fmt.Println("at-11.")
// 				err := client.conn.WriteMessage(websocket.TextMessage, message)
// 				if err != nil {
// 					log.Printf("Error writing message to connection: %v\n", err)
// 					return
// 				}
// 				fmt.Println("at-12.")
// 			case <-time.After(time.Second * 30):
// 				err := client.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second*5))
// 				if err != nil {
// 					log.Printf("Error sending ping to client: %v\n", err)
// 					return
// 				}
// 			}
// 			fmt.Println("at-13.")
// 		}
// 	}()

// }

// 	for {
// 		_, message, err := client.conn.ReadMessage()
// 		if err != nil {
// 			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
// 				log.Printf("WebSocket error: %v\n", err)
// 			}
// 			break
// 		}
// 		// Check if the message is intended for a specific client
// 		if len(message) >= 2 && message[0] == '/' && unicode.IsDigit(rune(message[1])) {
// 			receiver := string(message[1])
// 			if receiver != receiverNumber {
// 				continue
// 			}
// 			found := false
// 			for c := range clients {
// 				if c.mobile_number == receiverNumber {
// 					c.send <- message[2:]
// 					found = true
// 					break
// 				}
// 			}
// 			if !found {
// 				log.Printf("Could not find client with mobile number %s", receiverNumber)
// 			}
// 		} else {
// 			// Broadcast the message to all clients
// 			broadcast <- message
// 		}
// 	}
// }()
