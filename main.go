package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/xlzd/gotp"
	"go.etcd.io/bbolt"
)

type User struct {
	Username string
	Email    string
	OTP      string
}

// var users map[string]User

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
}

type RegisterResponse struct {
	StatusCode int    `json:"status_code"`
	UserID     string `json:"user_id"`
}

type ValidateOTPRequest struct {
	OTP   string `json:"otp" binding:"required"`
	Email string `json:"email" binding:"required"`
}

type ErrorResponse struct {
	StatusCode int    `json:"status_code"`
	Error     string `json:"error"`
	Message   string `json:"message"`
}

type SuccessResponse struct {
	StatusCode int         `json:"status_code"`
	Message    string      `json:"message"`
	Data       interface{} `json:"data,omitempty"`
}

var db *bbolt.DB
var adminToken string

func main() {
	// users = make(map[string]User)

	// Open the bbolt database
	var err error
	db, err = bbolt.Open("otp_users.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create a bucket for users if it doesn't exist
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("Users"))
		return err
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create a bucket for one-time-use if it doesn't exist
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("OneTimeUse"))
		return err
	})
	if err != nil {
		log.Fatal(err)
	}

	adminToken = os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = "your-secret"
	}

	router := gin.Default()

	// Add CORS middleware
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true // Allow all origins. Adjust this to your needs.
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}
	router.Use(cors.New(config))

	// Serve static files
	router.Static("/public", "./public")

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	api := router.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, SuccessResponse{
				StatusCode: http.StatusOK,
				Message:    "OK",
				Data:       time.Now().Unix(),
			})
		})
		api.POST("/register", registerUser)
		api.POST("/verify", validateOTP)
		api.GET("/qr/:id", renderQR)
	}

	admin := router.Group("/admin")
	{
		admin.Use(tokenAuthMiddleware())
		admin.DELETE("/flush-one-time-use", flushOneTimeUse)
		admin.DELETE("/delete-otu", deleteOneTimeUse)
		admin.DELETE("/flush-users", flushUsers)
		admin.DELETE("/delete-user", deleteUser)
	}

	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	router.Run(":" + port)
}

func registerUser(c *gin.Context) {
	var request RegisterRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			StatusCode: http.StatusBadRequest,
			Error:     "Bad Request",
			Message:   err.Error(),
		})
		return
	}

	// Generate unique identifier from email
	uniqueID := generateUniqueID(request.Email)
	// Generate OTP
	otp := gotp.RandomSecret(16) //always generate new otp
	var user User

	// Check if user already exists and write data if not
	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		v := b.Get([]byte(uniqueID))
		if v != nil {			
			json.Unmarshal(v, &user)
		}

		// Store user data
		user := User{
			Username: request.Username,
			Email:    request.Email,
			OTP:      otp,
		}

		userBytes, _ := json.Marshal(user)
		err := b.Put([]byte(uniqueID), userBytes)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	// Return response
	c.JSON(http.StatusOK, SuccessResponse{
		StatusCode: http.StatusCreated,
		Message:    "User registered successfully",
		Data:     uniqueID,
	})
}

func renderQR(c *gin.Context) {
	uniqueID := c.Param("id")

	// Check if the endpoint has already been accessed
	alreadyAccessed := false
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("OneTimeUse"))
		v := b.Get([]byte(uniqueID))
		if v != nil {
			alreadyAccessed = true
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	if alreadyAccessed {
        c.JSON(http.StatusForbidden, ErrorResponse{
			StatusCode: http.StatusForbidden,
			Error:     "Forbidden",
			Message:   "This endpoint has already been accessed",
		})
        return
    }
	
	// Look up user in the database
	var user User
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		v := b.Get([]byte(uniqueID))
		if v == nil {
			return fmt.Errorf("user not found")
		}
		json.Unmarshal(v, &user)
		return nil
	})
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			StatusCode: http.StatusNotFound,
			Error:     "Not Found",
			Message:   "User not found",
		})
		return
	}

	// Mark the endpoint as accessed
	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("OneTimeUse"))
		err := b.Put([]byte(uniqueID), []byte("accessed"))
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	// Generate QR code URI
	otpURI := gotp.NewDefaultTOTP(user.OTP).ProvisioningUri(user.Email, "supervision")

	// Render template with QR image path
	c.HTML(http.StatusOK, "index.html", gin.H{"otpURI": otpURI})
}

func validateOTP(c *gin.Context) {
	var requestBody ValidateOTPRequest

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			StatusCode: http.StatusBadRequest,
			Error:     "Bad Request",
			Message:   err.Error(),
		})
		return
	}

	// Validate the OTP here. This is just a placeholder.
	isValid := validateOTPFunction(requestBody.Email, requestBody.OTP)

	if isValid {
		c.JSON(http.StatusOK, SuccessResponse{
			StatusCode: http.StatusOK,
			Message:    "OTP is valid",
			Data: 	 nil,
		})
	} else {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			StatusCode: http.StatusUnauthorized,
			Error:     "Unauthorized",
			Message:   "Invalid OTP",
		})
	}
}

func validateOTPFunction(email string, otp string) bool {
	// Generate unique identifier from email
	uniqueID := generateUniqueID(email)

	// Look up user in the database
	var user User
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		v := b.Get([]byte(uniqueID))
		if v == nil {
			return fmt.Errorf("user not found")
		}
		json.Unmarshal(v, &user)
		return nil
	})
	if err != nil {
		log.Printf("User not found: %v", err)
		return false
	}


	// Check if the OTP is valid
	return gotp.NewDefaultTOTP(user.OTP).Now() == otp
}

func generateUniqueID(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}


// Middleware for token authentication
func tokenAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")

        // Check if the token is correct
        if token != adminToken {
            c.JSON(http.StatusUnauthorized, ErrorResponse{
				StatusCode: http.StatusUnauthorized,
				Error:     "Unauthorized",
				Message:   "Invalid token",
			})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Handler for flushing the OneTimeUse bucket
func flushOneTimeUse(c *gin.Context) {
    err := db.Update(func(tx *bbolt.Tx) error {
        err := tx.DeleteBucket([]byte("OneTimeUse"))
        if err != nil {
            return err
        }

        _, err = tx.CreateBucket([]byte("OneTimeUse"))
        return err
    })
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{
		StatusCode: http.StatusOK,
		Message:    "OneTimeUse bucket flushed",
		Data: 	 nil,
	})
}

// Handler for delete UniqueId from OneTimeUse bucket
func deleteOneTimeUse(c *gin.Context) {
	var request RegisterRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			StatusCode: http.StatusBadRequest,
			Error:     "Bad Request",
			Message:   err.Error(),
		})
		return
	}

	// Generate unique identifier from email
	uniqueID := generateUniqueID(request.Email)

	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("OneTimeUse"))
		err := b.Delete([]byte(uniqueID))
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		StatusCode: http.StatusOK,
		Message:    "OneTimeUse deleted",
		Data: 	 uniqueID,
	})
}

// Handler for flushing the Users bucket
func flushUsers(c *gin.Context) {
	err := db.Update(func(tx *bbolt.Tx) error {
		err := tx.DeleteBucket([]byte("Users"))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucket([]byte("Users"))
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		StatusCode: http.StatusOK,
		Message:    "Users bucket flushed",
		Data: 	 nil,
	})
}

// Handler for delete UniqueId from Users bucket
func deleteUser(c *gin.Context) {
	var request RegisterRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			StatusCode: http.StatusBadRequest,
			Error:     "Bad Request",
			Message:   err.Error(),
		})
		return
	}

	// Generate unique identifier from email
	uniqueID := generateUniqueID(request.Email)

	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		err := b.Delete([]byte(uniqueID))
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			StatusCode: http.StatusInternalServerError,
			Error:     "Internal Server Error",
			Message:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		StatusCode: http.StatusOK,
		Message:    "User deleted",
		Data: 	 uniqueID,
	})
}
