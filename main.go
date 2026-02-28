package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// VULNERABILITY: Hardcoded secrets and credentials
const (
	JWTSecret         = "contoso-gateway-jwt-secret-key-2024-production"
	AdminAPIKey       = "gateway-admin-api-key-xK9mP2nQ7wR4tY6u"
	InternalAuthToken = "internal-service-token-a1b2c3d4e5f6g7h8"

	// VULNERABILITY: Hardcoded database credentials for session store
	RedisPassword = "G@tew@yR3dis!2024"
	RedisHost     = "contoso-gateway-redis.redis.cache.windows.net:6380"

	// VULNERABILITY: Hardcoded cloud credentials
	AzureStorageKey   = "fAkEgAtEwAyStOrAgEkEy123456789ABCDEF=="
	AWSAccessKeyID    = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretKey      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// Service routes configuration
var serviceRoutes = map[string]string{
	"/api/users":    "http://user-service:8001",
	"/api/orders":   "http://order-service:8002",
	"/api/products": "http://product-service:8003",
	"/api/payments": "http://payment-service:8004",
	"/api/reports":  "http://report-service:8005",
}

func main() {
	gin.SetMode(gin.DebugMode) // VULNERABILITY: Debug mode in production

	r := gin.Default()

	// VULNERABILITY: CORS allows everything
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "*")
		c.Header("Access-Control-Allow-Headers", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"version": "1.0.0",
			// VULNERABILITY: Exposing internal service endpoints
			"services": serviceRoutes,
		})
	})

	// VULNERABILITY: Debug endpoint exposes all secrets
	r.GET("/debug/config", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"jwt_secret":      JWTSecret,
			"admin_api_key":   AdminAPIKey,
			"redis_host":      RedisHost,
			"redis_password":  RedisPassword,
			"aws_access_key":  AWSAccessKeyID,
			"aws_secret_key":  AWSSecretKey,
			"azure_storage":   AzureStorageKey,
			"service_routes":  serviceRoutes,
		})
	})

	// Login endpoint
	r.POST("/auth/login", handleLogin)

	// Token validation
	r.GET("/auth/validate", handleValidateToken)

	// Proxy routes with broken auth
	r.Any("/api/*path", handleProxy)

	// Admin routes
	r.GET("/admin/logs", handleAdminLogs)
	r.POST("/admin/exec", handleAdminExec)

	// VULNERABILITY: TLS configuration with InsecureSkipVerify
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,                    // VULNERABILITY
			MinVersion:         tls.VersionTLS10,        // VULNERABILITY: Allowing TLS 1.0
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,            // VULNERABILITY: Weak cipher
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
	}

	log.Printf("Contoso API Gateway starting on :8080")
	log.Fatal(server.ListenAndServe())
}

func handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// VULNERABILITY: Hardcoded credentials
	validUsers := map[string]string{
		"admin":       "admin123",
		"service_acc": "ServiceP@ss!2024",
		"developer":   "DevT3st!",
	}

	if pass, ok := validUsers[req.Username]; ok && pass == req.Password {
		// VULNERABILITY: JWT with no expiration and weak signing
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": req.Username,
			"role":     "admin", // VULNERABILITY: Everyone gets admin
			"iat":      time.Now().Unix(),
			// No expiration set - VULNERABILITY
		})

		tokenString, _ := token.SignedString([]byte(JWTSecret))
		c.JSON(200, gin.H{"token": tokenString})
	} else {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
	}
}

func handleValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(401, gin.H{"error": "No token provided"})
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	// VULNERABILITY: Not verifying token signature properly
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWTSecret), nil
	})

	if token != nil {
		c.JSON(200, gin.H{"valid": true, "claims": token.Claims})
	} else {
		c.JSON(401, gin.H{"valid": false})
	}
}

func handleProxy(c *gin.Context) {
	path := c.Param("path")
	fullPath := "/api" + path

	// Find matching service
	var targetURL string
	for prefix, target := range serviceRoutes {
		if strings.HasPrefix(fullPath, prefix) {
			targetURL = target
			break
		}
	}

	if targetURL == "" {
		c.JSON(404, gin.H{"error": "Service not found"})
		return
	}

	// VULNERABILITY: No authentication check on proxy routes
	// VULNERABILITY: No rate limiting

	target, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// VULNERABILITY: Insecure transport for backend connections
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func handleAdminLogs(c *gin.Context) {
	// VULNERABILITY: No authentication for admin endpoint
	// VULNERABILITY: Path traversal via query parameter
	logFile := c.DefaultQuery("file", "/var/log/gateway/access.log")

	data, err := os.ReadFile(logFile)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.String(200, string(data))
}

func handleAdminExec(c *gin.Context) {
	// VULNERABILITY: Remote command execution
	var req struct {
		Command string `json:"command"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// VULNERABILITY: Only checking API key, which is hardcoded and known
	apiKey := c.GetHeader("X-Admin-Key")
	if apiKey != AdminAPIKey {
		c.JSON(403, gin.H{"error": "Forbidden"})
		return
	}

	// VULNERABILITY: Command injection via os/exec
	cmd := fmt.Sprintf("sh -c '%s'", req.Command)
	_ = cmd // Would execute command

	c.JSON(200, gin.H{"status": "executed"})
}

// VULNERABILITY: Private key committed to repository
var privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGGRwFEMNqxKDQxGcXHzJy0F
g5KhDWP0AEFXKAJ6MDxaB3B7Qp3EEr0dKth8EQ0BdKZai5o7Uy3GHJK1z3T9Vy0w
fakePRIVATEkeyDATAhereNOTrealBUTlooksREALISTIC7890abcdef
ghijklmnopRSTUVWXYZexampleKEYdataFORdemoONLYnotACTUAL
realKEYjustPLACEHOLDERforSECURITYdemoPURPOSESonly123456
-----END RSA PRIVATE KEY-----`

func init() {
	// VULNERABILITY: Logging sensitive configuration at startup
	log.Printf("Gateway starting with JWT secret: %s", JWTSecret)
	log.Printf("Admin API key: %s", AdminAPIKey)
	log.Printf("Redis: %s (password: %s)", RedisHost, RedisPassword)

	// Write PID file
	_ = os.WriteFile("/tmp/gateway.pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)

	// VULNERABILITY: Reading private key from hardcoded variable  
	_ = io.Discard
	log.Printf("Private key loaded: %d bytes", len(privateKeyPEM))
}
