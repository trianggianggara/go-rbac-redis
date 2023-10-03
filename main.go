package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

var jwtSecret = []byte("secretKey")
var ctx = context.Background()
var redisClient *redis.Client

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type Zona struct {
	Name string `json:"name"`
	ID   uint   `json:"id"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func generateToken(userID int, userRole string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":   userID,
		"userRole": userRole,
		"exp":      time.Now().Add(time.Hour * 2).Unix(),
	})

	return token.SignedString(jwtSecret)
}

func parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		bearerToken := r.Header.Get("Authorization")

		tokenString := strings.Replace(bearerToken, "Bearer ", "", -1)

		token, err := parseToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		userID := int(token.Claims.(jwt.MapClaims)["userID"].(float64))
		userRole, err := getSession(userID)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r.Header.Set("UserRole", userRole)
		next.ServeHTTP(w, r)
	})
}

func setSession(userID int, userRole string) error {
	userIDStr := strconv.Itoa(userID)
	return redisClient.HSet(ctx, "sessions", userIDStr, userRole).Err()
}

func getSession(userID int) (string, error) {
	userIDStr := strconv.Itoa(userID)
	return redisClient.HGet(ctx, "sessions", userIDStr).Result()
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	fileContent, err := os.ReadFile("users.json")
	if err != nil {
		fmt.Println("Error reading the file:", err)
		return
	}

	// Define a slice to hold the users
	var users []User

	// Unmarshal the JSON data into the users slice
	err = json.Unmarshal(fileContent, &users)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	var authenticatedUser User
	for _, user := range users {
		if user.Username == loginReq.Username && user.Password == loginReq.Password {
			authenticatedUser = user
			break
		}
	}

	if authenticatedUser.ID == 0 {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := generateToken(authenticatedUser.ID, authenticatedUser.Role)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	response := map[string]string{
		"token": token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getPersonHandler(w http.ResponseWriter, r *http.Request) {

	person := new(Person)

	person.Name = "Anggi"
	person.Age = 30

	jsonPerson, err := json.Marshal(person)
	if err != nil {
		fmt.Println("Error", err.Error())
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	w.Write(jsonPerson)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Header.Get("UserRole")
	if userRole != "admin" {
		http.Error(w, "Access denied. Insufficient privileges.", http.StatusForbidden)
		return
	}

	response := map[string]string{
		"message": "success",
		"role":    userRole,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func editorHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Header.Get("UserRole")
	if userRole != "editor" {
		http.Error(w, "Access denied. Insufficient privileges.", http.StatusForbidden)
		return
	}

	response := map[string]string{
		"message": "success",
		"role":    userRole,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	fileContent, err := os.ReadFile("users.json")
	if err != nil {
		fmt.Println("Error reading the file:", err)
		return
	}

	// Define a slice to hold the users
	var users []User

	// Unmarshal the JSON data into the users slice
	err = json.Unmarshal(fileContent, &users)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	for _, user := range users {
		err := setSession(user.ID, user.Role)
		if err != nil {
			fmt.Printf("Error setting session for user %d: %v\n", user.ID, err)
		}
	}

	router := mux.NewRouter()
	http.Handle("/", AuthMiddleware(router))

	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/person", getPersonHandler).Methods("GET")
	router.HandleFunc("/admin", adminHandler).Methods("GET")
	router.HandleFunc("/admin", adminHandler).Methods("GET")

	fmt.Println("Server started on :8080")
	http.ListenAndServe("localhost:8080", nil)
}
