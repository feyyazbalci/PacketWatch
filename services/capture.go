package services

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gorm.io/gorm"

	"packetwatch/models"
)

type CaptureService struct {
	db *gorm.DB
	handle *pcap.Handle
	isRunning bool
	stopChan chan bool

	PacketCount int64
	StartTime time.Time
}

func NewCaptureService(db *gorm.DB) *CaptureService {
	return &CaptureService{
		db: db,
		stopChan: make(chan bool)
	}
}

