package handlers

import (
	// "bytes"
	"encoding/json"

	// "os"

	"net/http"
	"poc/task/auth"
	"poc/task/db"
	"poc/task/models"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"

	// "bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"io/ioutil"
	// "github.com/gorilla/mux"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	// "github.com/pdfcpu/pdfcpu"
	"golang.org/x/crypto/bcrypt"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	Subprotocols:    []string{"13"},
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	// Add the WebSocket version to the list of supported versions
	// Note that the supported versions should be in descending order
	// of preference, with the most recent version listed first
	HandshakeTimeout:  500 * time.Second,
	EnableCompression: false,
	Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		log.Println("WebSocket error:", reason)
		http.Error(w, "Internal server error", status)
	},
}

var jwtKey = []byte("secret")

func HandleRegistration(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In Registration")
	var user models.User
	if r.Body == nil {
		http.Error(w, "Request Body Is Empty", http.StatusBadRequest)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := db.GetUserFromRedis(user.MobileNumber)
	if res != nil {
		http.Error(w, "User Already exists!", http.StatusForbidden)
		return
	}

	if err != nil && err != redis.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)
	err = db.AddUserToRedis(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var loginreq models.LoginReq
	err := json.NewDecoder(r.Body).Decode(&loginreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	storedUser, err := db.GetUserFromRedis(loginreq.MobileNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(loginreq.Password))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	tokenString, err := auth.GenerateToken(loginreq.MobileNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(tokenString))
}

func HandleSendMessage(w http.ResponseWriter, r *http.Request) {
	var message models.Message
	fmt.Println("At-1")
	err := json.NewDecoder(r.Body).Decode(&message)
	fmt.Println("At-2")
	fmt.Println(message.To)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("At-3")
	tokenString := r.Header.Get("Authorization")[7:]
	fmt.Println(tokenString)
	fmt.Println("At-4")

	token, err := auth.ParseToken(tokenString)
	fmt.Println("At-5")
	if token == nil {
		fmt.Println("token Is Empty!")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Print("Token: ")
	fmt.Println(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println("Tokenstring:")
	fmt.Println(tokenString)
	if message.To == "" {
		http.Error(w, "Add Receipent Number!!", http.StatusUnauthorized)
		return
	}
	exists, err := CheckIfNumberExists(message.To)
	if !exists {
		http.Error(w, "Receipent Number Not Found In Records!!", http.StatusUnauthorized)
		return
	}

	if token.Valid {
		message.ID, err = db.GetNextMessageID()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println("At-11")
		fmt.Printf("Time:%s", message.Timestamp)
		fmt.Println()
		message.From = token.Claims.(jwt.MapClaims)["mobile_number"].(string)
		message.Timestamp = time.Now().Format(time.RFC3339)
		fmt.Println()
		fmt.Printf("Time Format:%s", message.Timestamp)
		fmt.Println()
		Time := string(message.Timestamp)
		fmt.Println()
		fmt.Printf("Time:%s", Time)
		fmt.Println()
		message.Timestamp = Time
		fmt.Printf("Time stamp:%s", message.Timestamp)
		fmt.Println()
		err = db.AddMessageToRedis(message)
		fmt.Println("At-12")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Println("At-13")
	json.NewEncoder(w).Encode(message)
	w.WriteHeader(http.StatusCreated)
}

func CheckIfNumberExists(number string) (bool, error) {
	// create Redis client
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Ping Redis to check if it's alive
	_, err := client.Ping().Result()
	if err != nil {
		return false, err
	}

	// check if the phone number exists in the Redis DB
	exists, err := client.Exists(number).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func HandleGetInbox(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := auth.ParseToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if token.Valid {
		messages, err := db.GetInboxFromRedis(token.Claims.(jwt.MapClaims)["mobile_number"].(string))

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, message := range messages {
			json.NewEncoder(w).Encode(message)
			fmt.Println()
		}

		// json.NewEncoder(w).Encode(messages)
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

}

func HandleGetOutbox(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := auth.ParseToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if token.Valid {
		messages, err := db.GetOutboxFromRedis(token.Claims.(jwt.MapClaims)["mobile_number"].(string))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(messages)
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
}

func HandleOutboxDocuments(w http.ResponseWriter, r *http.Request) {

	// check if user is authorized
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := auth.ParseToken(tokenString)

	if !token.Valid {
		http.Error(w, "Invalid Token!!", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "!ok in claims", http.StatusInternalServerError)
		return
	}
	Sender, ok := claims["mobile_number"]
	if !ok {
		http.Error(w, "!ok in sender", http.StatusInternalServerError)
		return
	}
	// get all documents in user's inbox

	outboxKey := fmt.Sprintf("user:%s:outbox", Sender)
	documents, err := db.GetDocumentsFromOutbox(outboxKey)
	// fmt.Println(documents)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// extract document URLs
	var urls []string
	var to []string
	for _, doc := range documents {
		urls = append(urls, doc.DocumentURL)
		to = append(to, doc.Receipent)
	}

	// return success response with JSON array of URLs
	jsonResponse := map[string]interface{}{"urls": urls, "to": to}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponse)

}

func HandleGetInboxDocuments(w http.ResponseWriter, r *http.Request) {
	// check if user is authorized
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := auth.ParseToken(tokenString)

	if !token.Valid {
		http.Error(w, "Invalid Token!!", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "!ok in claims", http.StatusInternalServerError)
		return
	}
	Sender, ok := claims["mobile_number"]
	if !ok {
		http.Error(w, "!ok in sender", http.StatusInternalServerError)
		return
	}
	// get all documents in user's inbox

	inboxKey := fmt.Sprintf("user:%s:inbox", Sender)
	documents, err := db.GetDocumentsFromInbox(inboxKey)
	fmt.Println(documents)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// extract document URLs
	var urls []string
	var sender []string
	for _, doc := range documents {
		urls = append(urls, doc.DocumentURL)
		sender = append(sender, doc.Sender)
	}

	// return success response with JSON array of URLs
	jsonResponse := map[string]interface{}{"urls": urls, "sender": sender}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponse)

}

var ctx = context.Background()

func HandleSendDocument(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	receiverNumber := vars["receiver_number"]
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := auth.ParseToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	exists, err := CheckIfNumberExists(receiverNumber)
	if !exists {
		http.Error(w, "Receipent Number Not Found In Records!!", http.StatusBadRequest)
		return
	}
	if token.Valid {

		//check if file is pdf or not
		file, _, err := r.FormFile("document")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
		// verify file format
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			http.Error(w, "Error Reading File!", http.StatusBadRequest)
			return
		}

		fmt.Printf("FileByte Length is: %d bytes/n", len(fileBytes))
		fmt.Println()
		if !isPDF(fileBytes) {
			http.Error(w, "File is not pdf!", http.StatusBadRequest)
			return
		}
		documentID := uuid.New()

		documentURL, err := UploadToGCP(documentID, fileBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		claims, _ := token.Claims.(jwt.MapClaims)
		SendermobileNumber, _ := claims["mobile_number"].(string)
		fmt.Printf("Sender is:%s", SendermobileNumber)

		document := models.Document{
			ID:          documentID,
			Sender:      SendermobileNumber,
			Receipent:   receiverNumber,
			DocumentURL: documentURL,
			Timestamp:   time.Now().Format(time.RFC3339),
		}

		// add documents to sender's outbox
		outboxKey := fmt.Sprintf("user:%s:outbox", SendermobileNumber)
		err = db.AddDocumentToOutbox(outboxKey, document)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// add document to receiver's inbox
		inboxKey := fmt.Sprintf("user:%s:inbox", receiverNumber)
		err = db.AddDocumentToInbox(inboxKey, document)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// return response
		json.NewEncoder(w).Encode(document)
		fmt.Printf("FileByte Length is: %d bytes/n", len(fileBytes))
		fmt.Println()
		w.WriteHeader(http.StatusOK)

	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
}
func UploadToGCP(documentID uuid.UUID, fileBytes []byte) (string, error) {
	fmt.Printf("File Type: %T\n", fileBytes)

	// Set up the GCP authentication credentials using the service account key file provided by someone else.
	ctx := context.Background()
	credentials, err := storage.NewClient(ctx, option.WithCredentialsFile("/home/sachin/Documents/gcp/storage-dev.json"))
	if err != nil {
		return "", fmt.Errorf("failed to create GCS client: %v", err)
	}

	// Create a new GCS bucket object.
	// Replace "my-gcs-bucket" with the name of your GCS bucket.
	bucketName := "chat-app-poc"
	bucket := credentials.Bucket(bucketName)

	// Create a new GCS object with the given document ID as its name.
	object := bucket.Object(documentID.String())

	// Create a new GCS writer object to upload the file contents to GCS.
	writer := object.NewWriter(ctx)
	writer.ContentType = "application/pdf"

	// Copy the file contents to the GCS writer object.
	totalBytes := int64(len(fileBytes))
	fmt.Println(totalBytes)
	reader := bytes.NewReader(fileBytes)
	if _, err := io.Copy(writer, reader); err != nil {
		writer.Close()
		return "", fmt.Errorf("failed to upload file to GCS: %v", err)
	}

	// Wait for the writer to return a nil error after closing it, indicating that the object has finished uploading.
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close object: %v", err)
	}

	// Ensure that the file was successfully uploaded by checking its size.
	attrs, err := object.Attrs(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve object attributes: %v", err)
	}
	if attrs.Size == 0 {
		return "", fmt.Errorf("file was uploaded but has a size of 0 bytes")
	}

	// Return the URL of the uploaded file.
	url := fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucketName, documentID)
	return url, nil
}

func isPDF(fileBytes []byte) bool {
	return len(fileBytes) > 4 && string(fileBytes[0:4]) == "%PDF"
}
