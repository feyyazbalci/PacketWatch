package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"packetwatch/models"
)

type PacketHandler struct {
	db *gorm.DB
}

// NewPacketHandler - Creates a new PacketHandler
func NewPacketHandler(db *gorm.DB) *PacketHandler {
	return &PacketHandler(db:db)
}

func (h *PacketHandler) GetPackets(c *fiber.Ctx) error {
   // Query parameters
   page, _ := strconv.Atoi(c.Query("page", "1"))
   limit, _ := strconv.Atoi(c.Query("limit", "20"))
   protocol := c.Query("protocol")

   if page < 1 {
	  page = 1
   }
   if limit < 1 || limit > 100 {
	  limit = 50
   }

   offset := (page - 1) * limit

   query := h.db.Model(&models.Packet{})

   if protocol != "" {
	  query = query.Where("protocol = ?", protocol)
   }

   var packets []models.Packet
   var total int64

   // Total count
   query.Count(&total)

   // Actual data with pagination
   result := query.Order("created_at DESC").
   			Limit(limit).
			Offset(offset).
			Find(&packets)

    if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Database query failed"
		})
	}

	return c.JSON(fiber.Map{
		"data": packets,
		"pagination": fiber.Map{
			"page": page,
			"limit": limit,
			"total": total,
			"total_pages": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

func (h *PacketHandler) GetPacket(c *fiber.Ctx) error {
	id := c.Params("id")

	var packet models.Packet
	result := h.db.First(&packet, id)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{
				"error": "Packet not found",
			})
		}
		return c.Status(500).JSON(fiber.Map{
			"error": "Database query failed",
		})
	}

	return c.JSON(fiber.Map{
		"data": packet
	})
}

func (h *PacketHandler) CreatePacket(c *fiber.Ctx) error {
	var packet models.Packet

	if err := c.BodyParser(&packet); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body"
		})
	}

	packet.Timestamp = time.Now()

	result := h.db.Create(&packet)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create packet",
		})
	}

	return c.Status(201).JSON(fiber.Map{
		"data": packet,
		"message": "Packet created successfully",
	})
}

func (h *PacketHandler) DeletePacket(c *fiber.Ctx) error {
	id := c.Params("id")

	result := h.db.Delete(&models.Packet{}, id)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to delete packet",
		})
	}

	if result.RowsAffected == 0 {
		return c.Status(404).JSON(fiber.Map{
			"error": "Packet not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Packet deleted successfully",
	})
}

func (h *PacketHandler) GetStats(c *fiber.Ctx) error {
	var stats models.PacketStats

	h.db.Model(&models.Packet{}).Count(&stats.TotalPackets)

	h.db.Model(&models.Packet{}).Select("COALESCE(SUM(size), 0)").Scan(&stats.TotalSize)

	var protocolResults []struct {
		Protocol string `json:"protocol"`
		Count int64 `json:"count"`
	}

	h.db.Model(&models.Packet{}).
		Select("protocol, COUNT(*) as count").
		Group("protocol").
		Scan(&protocolResults)

	stats.ProtocolCounts = make(map[string]int64)
	for _, result := range protocolResults {
		stats.ProtocolCounts[result.Protocol] = result.Count
 	}

	var ipResults []struct {
		IP    string `json:"ip"`
		Count int64  `json:"count"`
	}

	h.db.Model(&models.Packet{}).
		Select("source_ip as ip, COUNT(*) as count").
		Group("source_ip").
		Order("count DESC").
		Limit(10).
		Scan(&ipResults)

	stats.TopIPs = make([]models.IPCount, len(ipResults))
	for i, result := range ipResults {
		stats.TopIPs[i] = models.IPCount{
			IP:    result.IP,
			Count: result.Count,
		}
	}

	// Top ports
	var portResults []struct {
		Port  int   `json:"port"`
		Count int64 `json:"count"`
	}
	h.db.Model(&models.Packet{}).
		Select("dest_port as port, COUNT(*) as count").
		Where("dest_port > 0").
		Group("dest_port").
		Order("count DESC").
		Limit(10).
		Scan(&portResults)

	stats.TopPorts = make([]models.PortCount, len(portResults))
	for i, result := range portResults {
		stats.TopPorts[i] = models.PortCount{
			Port:  result.Port,
			Count: result.Count,
		}
	}

	// Last hour packets
	oneHourAgo := time.Now().Add(-time.Hour)
	h.db.Model(&models.Packet{}).
		Where("created_at > ?", oneHourAgo).
		Count(&stats.LastHour)

	return c.JSON(fiber.Map{
		"data": stats,
	})
}