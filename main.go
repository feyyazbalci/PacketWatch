package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"packetwatch/database"
	"packetwatch/handlers"
	"packetwatch/models"
)

func main() {
	db, err := database.Connect()
	if err != nil {
		log.Fatal("Database connection error:", err)
	}

	if err: = db.AutoMigrate(&models.Packet{}); err != nil {
		log.Fatal("Database migration error:", err)
	}

	app := fiber.New(fiber.Config{
		AppName: "PacketWatch v1.o",
	})

	app.Use(logger.New()) // Request logging
	app.Use(recover.New()) // Panic recovery
	app.Use(cors.New())  // CORS support

	// Initialize handlers
	packetHandler := handlers.NewPacketHandler(db)

	// Defina as rotas
	setupRoutes(app, packetHandler)

	port := getEnv("PORT", 8080)
	log.Printf("PacketWatch is running on port %d", port)
	log.Fatal(app.Listen(":" + port))
}

func setupRoutes(app *fiber.App, packetHandler *handlers.PacketHandler) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "PacketWatch API",
			"status": "running",
			"version": "1.0"
		})
	})

	api := app.Group("/api/v1")

	//Packet endpoints
	api.Get("/packets", packetHandler.GetAllPackets)
	api.Get("/packets/:id", packetHandler.GetPacket)
	api.Post("/packets", packetHandler.CreatePacket) // For testing purposes
	api.Delete("/packets/:id", packetHandler.DeletePacket)

	// Stats endpoint
	api.Get("/stats", packetHandler.GetStats)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}