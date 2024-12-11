package handlers

import (
	"context"
	"ecommerce-project/models"
	"encoding/json"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

// Admin structure
type Admin struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

func CreateAdmin(w http.ResponseWriter, r *http.Request) {
	var admin models.Admin
	_ = json.NewDecoder(r.Body).Decode(&admin)

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	admin.Password = string(hashedPassword)

	// Insert admin into the database
	collection := db.Collection("admins")
	_, err = collection.InsertOne(context.TODO(), admin)
	if err != nil {
		http.Error(w, "Error creating admin", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Admin added"))
}

func AdminLogin(w http.ResponseWriter, r *http.Request) {
	var admin models.Admin
	_ = json.NewDecoder(r.Body).Decode(&admin)

	collection := db.Collection("admins")
	var storedAdmin models.Admin
	fmt.Println("hello")
	// Find admin by username
	err := collection.FindOne(context.TODO(), bson.M{"username": admin.Username}).Decode(&storedAdmin)
	if err != nil {
		http.Error(w, "Invalid uuuuu", http.StatusUnauthorized)
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(storedAdmin.Password), []byte(admin.Password))
	if err != nil {
		http.Error(w, "Invalid dddde", http.StatusUnauthorized)
		return
	}

	// Success
	w.Write([]byte("Login success"))
}

func GetAdmin(w http.ResponseWriter, r *http.Request) {

	collection := db.Collection("admins")
	// Find admin by username
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Error fetching admins", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var admins []models.Admin
	if err = cursor.All(context.TODO(), &admins); err != nil {
		http.Error(w, "Error reading admins", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(admins)
}

// func GetProducts(w http.ResponseWriter, r *http.Request) {
// 	collection := db.Collection("products")

// 	cursor, err := collection.Find(context.TODO(), bson.M{})
// 	if err != nil {
// 		http.Error(w, "Error fetching products", http.StatusInternalServerError)
// 		return
// 	}
// 	defer cursor.Close(context.TODO())

// 	var products []models.Product
// 	if err = cursor.All(context.TODO(), &products); err != nil {
// 		http.Error(w, "Error reading products", http.StatusInternalServerError)
// 		return
// 	}

// 	// Respond with products list
// 	w.Header().Set("Content-Type", "application/json")
// 	_ = json.NewEncoder(w).Encode(products)
// }
