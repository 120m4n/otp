package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

type User struct {
	Username string
	OTP      string
	QRPath   string // Path to QR image
}

var users map[string]User

func main() {
	users = make(map[string]User)

	router := gin.Default()

	// Serve static files
	router.Static("/public", "./public")

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	router.GET("/register", registerUser)
	router.GET("/qr/:id", renderQR)

	router.Run(":8080")
}

func registerUser(c *gin.Context) {
	// Generate unique identifier
	uniqueID := generateUniqueID()

	// Generate OTP
	otp := gotp.RandomSecret(16)

	// Generate QR code URI
	otpURI := gotp.NewDefaultTOTP(otp).ProvisioningUri("demoAccountName", "issuerName")

	// Save QR image to file
	qrPath, err := saveQR(uniqueID, otpURI)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Store user data
	users[uniqueID] = User{
		Username: c.Query("username"),
		OTP:      otp,
		QRPath:   qrPath,
	}

	// Redirect user to template-rendering page
	c.Redirect(http.StatusFound, "/qr/"+uniqueID)
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

func generateUniqueID() string {
	// Generate a random byte slice with length 12
	randomBytes := make([]byte, 12)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Handle error
		log.Fatal(err)
	}

	// Encode the random byte slice to base64
	encodedBytes := base64.StdEncoding.EncodeToString(randomBytes)

	// Remove special characters from the encoded string
	uniqueID := ""
	for _, c := range encodedBytes {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			uniqueID += string(c)
		}
	}

	// Trim the unique ID to length 16
	if len(uniqueID) > 16 {
		uniqueID = uniqueID[:16]
	}

	return uniqueID
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