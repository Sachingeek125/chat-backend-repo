package auth

import (
	// "encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

var jwtKey = []byte("secret")

type claims struct {
	MobileNumber string `json:"mobile_number"`
	jwt.StandardClaims
}

func GenerateToken(mobileNumber string) (string, error) {
	if mobileNumber == "" {
		return "", errors.New("Mobile number is required")
	}

	claims := &claims{
		MobileNumber: mobileNumber,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return "", fmt.Errorf("Error generating token: %v", err)
	}

	return tokenString, nil
}

func GenerateToken0(mobileNumber string) (string, error) {

	if mobileNumber == "" {
		return "", errors.New("Mobile number is required")
	}
	// Create a new token object with claims
	claims := jwt.MapClaims{
		"mobile_number": mobileNumber,
		"exp":           time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.New(jwt.SigningMethodHS256)

	token.Claims = claims

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return "", fmt.Errorf("Error generating token: %v", err)
	}

	parts := strings.Split(tokenString, ".")
	fmt.Printf("Total Parts: %d", len(parts))
	return tokenString, nil

}

func ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check that the signing method is HMAC and the key matches
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	if !token.Valid {
		return nil, errors.New("Invalid token")
	}

	return token, nil
}
