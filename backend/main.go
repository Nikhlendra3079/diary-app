package main

import (
	"log"
	"net/http"
	"os" // <--- ADDED: Necessary for Cloud Environment Variables
	"time"

	"github.com/gin-contrib/cors"
	// "github.com/gin-contrib/static" <--- REMOVED: Vercel will host the frontend, not Go.
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
	Content   string `gorm:"type:text"`
	Mood      string
	Date      string
	CreatedAt time.Time
}

// --- Global DB Variable ---
var db *gorm.DB
var jwtSecret = []byte("super-secret-key-change-this")

func main() {
	// 1. Database Connection (Dynamic)
	// We check if the cloud provided a database URL. If not, we use your local one.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Your LOCAL fallback (keep this for when you work on your laptop)
		dsn = "host=localhost user=postgres password=3079 dbname=diarydb port=5432 sslmode=disable"
	}

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 2. Auto Migrate
	db.AutoMigrate(&User{}, &Entry{})

	// 3. Setup Router
	r := gin.Default()

	// 4. CORS Setup (Updated for Cloud)
	// We allow ALL origins temporarily so Vercel can talk to Render easily.
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	r.Use(cors.New(config))

	// --- REMOVED STATIC FILE SERVING ---
	// Since we are using Vercel for the Frontend, the Go backend
	// strictly handles JSON data only. It does not serve HTML.

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

	// 6. Port Configuration (Dynamic)
	// Render assigns a random port (e.g., 10000). We must listen on that port.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default for local
	}
	r.Run(":" + port)
}

// --- Handlers (Keep these exactly the same) ---

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(),
	})
	tokenString, _ := token.SignedString(jwtSecret)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func createEntry(c *gin.Context) {
	userID := c.GetFloat64("userID")
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
