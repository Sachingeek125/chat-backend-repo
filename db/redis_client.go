package db

import (
	// "context"
	"encoding/json"
	// "mime/multipart"

	"fmt"
	"poc/task/models"

	"log"
	// "time"

	// "cloud.google.com/go/storage"
	"github.com/go-redis/redis"
)

var client *redis.Client
var inBox = make(map[string]models.Message)

func ConnectToRedis() {
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

func AddUserToRedis(user models.User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	err = client.Set(user.MobileNumber, data, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

func GetUserFromRedis(mobileNumber string) (*models.User, error) {
	val, err := client.Get(mobileNumber).Result()
	if err != nil {
		return nil, err
	}
	var user models.User
	err = json.Unmarshal([]byte(val), &user)

	if err != nil {
		log.Printf("error decoding sakura response: %v", err)
		if e, ok := err.(*json.SyntaxError); ok {
			log.Printf("syntax error at byte offset %d", e.Offset)
		}
		log.Printf("sakura response: %q", user)
		return nil, err
	}

	// if err != nil {
	// 	return nil, err
	// }
	return &user, nil

}

func AddMessageToRedis(message models.Message) error {
	json, err := json.Marshal(message)
	if err != nil {
		return err
	}
	err = client.LPush("messages:"+message.To, json).Err()
	if err != nil {
		return err
	}
	return nil
}
func GetInboxFromRedis(mobileNumber string) ([]models.Message, error) {
	messages := []models.Message{}
	vals, err := client.LRange("messages:"+mobileNumber, 0, -1).Result()
	if err != nil {
		return nil, err
	}
	for _, val := range vals {
		var message models.Message
		err = json.Unmarshal([]byte(val), &message)

		log.Printf("sakura response: %q", message)

		messages = append(messages, message)
	}

	return messages, nil
}

func GetInboxFromRedis2(mobileNumber string) ([]models.Message, error) {
	messages := []models.Message{}
	vals, err := client.LRange("messages:"+mobileNumber, 0, -1).Result()
	if err != nil {
		return nil, err
	}
	for _, val := range vals {
		var message models.Message
		err = json.Unmarshal([]byte(val), &message)
		if err != nil {
			log.Printf("error decoding sakura response: %v", err)
			if e, ok := err.(*json.SyntaxError); ok {
				log.Printf("syntax error at byte offset %d", e.Offset)
			}
			log.Printf("sakura response: %q", message)
			return nil, err
		}

		messages = append(messages, message)
	}
	return messages, nil
}

func GetOutboxFromRedis(mobileNumber string) ([]models.Message, error) {
	messages := []models.Message{}
	vals, err := client.Keys("messages:*").Result()
	if err != nil {
		return nil, err
	}
	for _, key := range vals {
		vals, err = client.LRange(key, 0, -1).Result()
		if err != nil {
			return nil, err

		}
		for _, val := range vals {
			var message models.Message
			err = json.Unmarshal([]byte(val), &message)

			log.Printf("sakura response: %q", message)
			if message.From == mobileNumber {
				messages = append(messages, message)
			}

		}

	}
	return messages, nil

}

func AddDocumentToOutbox(outboxKey string, document models.Document) error {
	// marshal document to JSON string
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("Error marshaling document: %v", err)
	}

	// add document to outbox list
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	_, err = client.RPush(outboxKey, documentJSON).Result()
	if err != nil {
		return fmt.Errorf("Error adding document to outbox: %v", err)
	}

	return nil
}

func GetDocumentsFromOutbox(outboxKey string) ([]models.Document, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	// get all documents in outbox
	docStrings, err := client.LRange(outboxKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("Error getting documents from inbox: %v", err)
	}

	// unmarshal documents from JSON strings
	var documents []models.Document
	for _, docString := range docStrings {
		var doc models.Document
		err := json.Unmarshal([]byte(docString), &doc)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling document: %v", err)
		}
		documents = append(documents, doc)
	}

	return documents, nil
}

func AddDocumentToInbox(inboxKey string, document models.Document) error {
	// marshal document to JSON string
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("Error marshaling document: %v", err)
	}

	fmt.Printf("Document Json:%s\n", documentJSON)

	// add document to outbox list
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	_, err = client.RPush(inboxKey, documentJSON).Result()
	if err != nil {
		return fmt.Errorf("Error adding document to outbox: %v", err)
	}

	return nil
}

func GetDocumentsFromInbox(inboxKey string) ([]models.Document, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	// get all documents in inbox
	docStrings, err := client.LRange(inboxKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("Error getting documents from inbox: %v", err)
	}

	// unmarshal documents from JSON strings
	var documents []models.Document
	for _, docString := range docStrings {
		var doc models.Document
		err := json.Unmarshal([]byte(docString), &doc)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling document: %v", err)
		}
		documents = append(documents, doc)
	}

	return documents, nil
}

func GetNextMessageID() (int64, error) {
	val, err := client.Incr("message_id").Result()
	if err != nil {
		return 0, err
	}
	return val, nil
}

func init() {
	ConnectToRedis()
}
