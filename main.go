package main

import (
	"context"
	"ecommerce-project/handlers"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

func main() {
	// Connect to MongoDB
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017") // Your MongoDB URI here
	client, err := mongo.Connect(context.Background(), clientOptions)       // Changed nil to context.Background()
	if err != nil {
		log.Fatal(err)
	}

	// Access the e-commerce database
	db = client.Database("ecommerce")

	// Initialize handlers
	handlers.InitializeHandlers(db)

	// Set up routes
	r := mux.NewRouter()

	// Admin routes
	r.HandleFunc("/admin/login", handlers.AdminLogin).Methods("POST")
	r.HandleFunc("/admin/create", handlers.CreateAdmin).Methods("POST")
	r.HandleFunc("/admins", handlers.GetAdmin).Methods("GET")
	r.HandleFunc("/admin/product/add", handlers.AddProduct).Methods("POST")
	r.HandleFunc("/admin/product/edit/{id}", handlers.EditProduct).Methods("PUT")
	r.HandleFunc("/admin/products", handlers.GetProducts).Methods("GET")

	// Start server
	http.Handle("/", r)
	log.Println("Server running at http://localhost:8080/")
	log.Fatal(http.ListenAndServe(":8080", nil)) // Server runs on port 8080
}