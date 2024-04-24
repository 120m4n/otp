package main

import (
	"fmt"
	"net/http"
	"strings"
	"crypto/sha256"
    "encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

type User struct {
	Username string
	Email    string
	OTP      string
	QRPath   string // Path to QR image
}

var users map[string]User

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
}

type RegisterResponse struct {
	StatusCode int    `json:"status_code"`
	QRURL      string `json:"qr_url"`
}

type ValidateOTPRequest struct {
	OTP string `json:"otp" binding:"required"`
	Email string `json:"email" binding:"required"`
}

func main() {
    users = make(map[string]User)

    router := gin.Default()

    // Serve static files
    router.Static("/public", "./public")

    // Load HTML templates
    router.LoadHTMLGlob("templates/*")

	router.POST("/register", registerUser)
    router.GET("/qr/:id", renderQR)
    router.POST("/validate-otp", validateOTP) // New line

    router.Run(":8080")
}

func registerUser(c *gin.Context) {
	var request RegisterRequest

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate unique identifier from email
	uniqueID := generateUniqueID(request.Email)

	// Check if user already exists
	if user, exists := users[uniqueID]; exists {
		// Create response with existing QR code path
		response := RegisterResponse{
			StatusCode: http.StatusOK,
			QRURL:      "http://localhost:8080/public/" + user.QRPath,
		}

		// Return response
		c.JSON(http.StatusOK, response)
		return
	}

	// Generate OTP
	otp := gotp.RandomSecret(16)

	// Generate QR code URI
	otpURI := gotp.NewDefaultTOTP(otp).ProvisioningUri(request.Email, "supervision")

	// Save QR image to file
	qrPath, err := saveQR(uniqueID, otpURI)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Store user data
	users[uniqueID] = User{
		Username: request.Username,
		Email:    request.Email,
		OTP:      otp,
		QRPath:   qrPath,
	}

	// Create response
	response := RegisterResponse{
		StatusCode: http.StatusCreated,
		QRURL:      "http://localhost:8080/public/" + uniqueID + ".png",
	}

	// Return response
	c.JSON(http.StatusCreated, response)
}

func renderQR(c *gin.Context) {
	id := c.Param("id")
	user, ok := users[id]
	if !ok {
		c.String(http.StatusNotFound, "User not found")
		return
	}

	// Remove "./public/" from the QRPath
	qrPath := strings.TrimPrefix(user.QRPath, "./public/")

	// Render template with QR image path
	c.HTML(http.StatusOK, "index.html", gin.H{"QRPath": "/public/" + qrPath})
}

func validateOTP(c *gin.Context) {
	var requestBody ValidateOTPRequest

	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the OTP here. This is just a placeholder.
	isValid := validateOTPFunction(requestBody.Email, requestBody.OTP)

	if isValid {
		c.JSON(http.StatusOK, gin.H{"status": "OTP is valid"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "OTP is invalid"})
	}
}

func validateOTPFunction(email string, otp string) bool {
	// Generate unique identifier from email
	uniqueID := generateUniqueID(email)

	// Look up user by unique identifier
	user, exists := users[uniqueID]
	if !exists {
		return false
	}

	// Check if the OTP is valid
	return gotp.NewDefaultTOTP(user.OTP).Now() == otp
}

func generateUniqueID(email string) string {
    hash := sha256.Sum256([]byte(email))
    return hex.EncodeToString(hash[:])
}


func saveQR(uniqueID, otpURI string) (string, error) {
	// Create a new QR code
	qrCode, err := qrcode.New(otpURI, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("could not generate QR Code: %v", err)
	}

	// Save the QR code to a file
	path := uniqueID + ".png"
	err = qrCode.WriteFile(256, "./public/" + path)
	if err != nil {
		return "", fmt.Errorf("could not write file: %v", err)
	}

	return path, nil
}