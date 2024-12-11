package handlers

import (
	"context"
	"ecommerce-project/models"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Product struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Price       float64            `bson:"price" json:"price"`
	Stock       int                `bson:"stock" json:"stock"`
}

func AddProduct(w http.ResponseWriter, r *http.Request) {
	var product models.Product
	_ = json.NewDecoder(r.Body).Decode(&product)

	// Insert product into the database
	collection := db.Collection("products")
	_, err := collection.InsertOne(context.TODO(), product)
	if err != nil {
		http.Error(w, "Error adding product", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Product added successfully"))
}

// Edit Product Handler
func EditProduct(w http.ResponseWriter, r *http.Request) {
	var product models.Product
	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		fmt.Println("Error decoding JSON:", err)
		return
	}

	vars := mux.Vars(r)
	productID := vars["id"]

	// Convert productID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		fmt.Println("Error converting productID to ObjectID:", err)
		return
	}

	// Update product details
	collection := db.Collection("products")
	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": objectID}, // Use ObjectID here
		bson.D{
			{"$set", bson.D{
				{"name", product.Name},
				{"description", product.Description},
				{"price", product.Price},
				{"stock", product.Stock},
			}},
		},
	)
	if err != nil {
		http.Error(w, "Error updating product", http.StatusInternalServerError)
		fmt.Println("Error updating product:", err)
		return
	}

	w.Write([]byte("Product updated successfully"))
}

// Get All Products Handler
func GetProducts(w http.ResponseWriter, r *http.Request) {
	collection := db.Collection("products")

	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var products []models.Product
	if err = cursor.All(context.TODO(), &products); err != nil {
		http.Error(w, "Error reading products", http.StatusInternalServerError)
		return
	}

	// Respond with products list
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(products)
}
