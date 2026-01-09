package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Database Models ---
type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"unique"`
	PasswordHash string
}

type Entry struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	Title     string
	Content   string `gorm:"type:text"` // Stores Encrypted Data
	Mood      string
	Date      string // Format YYYY-MM-DD
	CreatedAt time.Time
}

// --- Global DB Variable ---
var db *gorm.DB
var jwtSecret = []byte("super-secret-key-change-this")

func main() {
	// 1. Connect to Database
	// CHANGE 'postgres' (user) and 'password' to your real postgres credentials
	dsn := "host=localhost user=postgres password=3079 dbname=diarydb port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 2. Auto Migrate (Create tables automatically based on structs)
	db.AutoMigrate(&User{}, &Entry{})

	// 3. Setup Router
	r := gin.Default()

	// 4. CORS Setup (Allow frontend to talk to backend)
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5173"} // Vite default port
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	r.Use(cors.New(config))

	// ... inside main() ...
	// --- NEW: Serve Frontend Static Files ---
	// This tells Go: "If a user asks for '/', look in the '../frontend/dist' folder"
	r.Use(static.Serve("/", static.LocalFile("../frontend/dist", true)))

	// ----------------------------------------

	// ... existing routes (r.POST("/signup", ...)) ...
	// 5. Routes
	r.POST("/signup", signup)
	r.POST("/login", login)

	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.GET("/entries", getEntries)
		authorized.POST("/entries", createEntry)
		authorized.PUT("/entries/:id", updateEntry)
		authorized.DELETE("/entries/:id", deleteEntry)
	}

	r.Run(":8080")
}

// --- Handlers ---

func signup(c *gin.Context) {
	var body struct {
		Username string
		Password string
	}
	if c.BindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid body"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	user := User{Username: body.Username, PasswordHash: string(hash)}

	if result := db.Create(&user); result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User created"})
}

func login(c *gin.Context) {
	var body struct {
		Username string
		Password string
	}
	if c.BindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid body"})
		return
	}

	var user User
	db.Where("username = ?", body.Username).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 days
	})
	tokenString, _ := token.SignedString(jwtSecret)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func createEntry(c *gin.Context) {
	userID := c.GetFloat64("userID") // From Middleware
	var entry Entry
	if err := c.BindJSON(&entry); err != nil {
		return
	}
	entry.UserID = uint(userID)
	db.Create(&entry)
	c.JSON(http.StatusOK, entry)
}

func getEntries(c *gin.Context) {
	userID := c.GetFloat64("userID")
	search := c.Query("search")
	date := c.Query("date")

	var entries []Entry
	query := db.Where("user_id = ?", userID)

	// Note: We cannot search CONTENT on the server because it is encrypted!
	// We can only search Titles or Dates server-side.
	if search != "" {
		query = query.Where("title ILIKE ?", "%"+search+"%")
	}
	if date != "" {
		query = query.Where("date = ?", date)
	}

	query.Order("date desc").Find(&entries)
	c.JSON(http.StatusOK, entries)
}

func updateEntry(c *gin.Context) {
	id := c.Param("id")
	userID := c.GetFloat64("userID")
	var input Entry
	if err := c.BindJSON(&input); err != nil {
		return
	}

	var entry Entry
	if err := db.Where("id = ? AND user_id = ?", id, userID).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Entry not found"})
		return
	}

	db.Model(&entry).Updates(input)
	c.JSON(http.StatusOK, entry)
}

func deleteEntry(c *gin.Context) {
	id := c.Param("id")
	userID := c.GetFloat64("userID")
	db.Where("id = ? AND user_id = ?", id, userID).Delete(&Entry{})
	c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
}

// --- Middleware ---
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No token"})
			return
		}

		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("userID", claims["sub"])
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		}
	}
}
