package handlers

import (
	"go.mongodb.org/mongo-driver/mongo"
)

var db *mongo.Database

// Initialize handlers
func InitializeHandlers(database *mongo.Database) {
	db = database
}

// // Admin Login Handler
// func AdminLogin(w http.ResponseWriter, r *http.Request) {
// 	var admin models.Admin
// 	_ = json.NewDecoder(r.Body).Decode(&admin)

// 	collection := db.Collection("admins")
// 	var storedAdmin models.Admin
// 	fmt.Println("hello")
// 	// Find admin by username
// 	err := collection.FindOne(context.TODO(), bson.M{"username": admin.Username}).Decode(&storedAdmin)
// 	if err != nil {
// 		http.Error(w, "Invalid uuuuu", http.StatusUnauthorized)
// 		return
// 	}

// 	// Check password
// 	err = bcrypt.CompareHashAndPassword([]byte(storedAdmin.Password), []byte(admin.Password))
// 	if err != nil {
// 		http.Error(w, "Invalid dddde", http.StatusUnauthorized)
// 		return
// 	}

// 	// Success
// 	w.Write([]byte("Login success"))
// }

// Create Admin Handler
// func CreateAdmin(w http.ResponseWriter, r *http.Request) {
// 	var admin models.Admin
// 	_ = json.NewDecoder(r.Body).Decode(&admin)

// 	// Hash password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		http.Error(w, "Error hashing password", http.StatusInternalServerError)
// 		return
// 	}
// 	admin.Password = string(hashedPassword)

// 	// Insert admin into the database
// 	collection := db.Collection("admins")
// 	_, err = collection.InsertOne(context.TODO(), admin)
// 	if err != nil {
// 		http.Error(w, "Error creating admin", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Write([]byte("Admin successfully added"))
// }

// Add Product Handler
// func AddProduct(w http.ResponseWriter, r *http.Request) {
// 	var product models.Product
// 	_ = json.NewDecoder(r.Body).Decode(&product)

// 	// Insert product into the database
// 	collection := db.Collection("products")
// 	_, err := collection.InsertOne(context.TODO(), product)
// 	if err != nil {
// 		http.Error(w, "Error adding product", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Write([]byte("Product added successfully"))
// }

// // Edit Product Handler
// func EditProduct(w http.ResponseWriter, r *http.Request) {
// 	var product models.Product
// 	err := json.NewDecoder(r.Body).Decode(&product)
// 	if err != nil {
// 		http.Error(w, "Invalid input", http.StatusBadRequest)
// 		fmt.Println("Error decoding JSON:", err)
// 		return
// 	}

// 	vars := mux.Vars(r)
// 	productID := vars["id"]

// 	// Convert productID to ObjectID
// 	objectID, err := primitive.ObjectIDFromHex(productID)
// 	if err != nil {
// 		http.Error(w, "Invalid product ID", http.StatusBadRequest)
// 		fmt.Println("Error converting productID to ObjectID:", err)
// 		return
// 	}

// 	// Update product details
// 	collection := db.Collection("products")
// 	_, err = collection.UpdateOne(
// 		context.TODO(),
// 		bson.M{"_id": objectID}, // Use ObjectID here
// 		bson.D{
// 			{"$set", bson.D{
// 				{"name", product.Name},
// 				{"description", product.Description},
// 				{"price", product.Price},
// 				{"stock", product.Stock},
// 			}},
// 		},
// 	)
// 	if err != nil {
// 		http.Error(w, "Error updating product", http.StatusInternalServerError)
// 		fmt.Println("Error updating product:", err)
// 		return
// 	}

// 	w.Write([]byte("Product updated successfully"))
// }

// // Get All Products Handler
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
