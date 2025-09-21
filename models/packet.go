package models

import (
	"time"

	"gorm.io/gorm"
)

// Packet represents a network packet record in the database
type Packet struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Packet fields
	SourceIP   string `json:"source_ip" gorm:"size:45;index;not null"`
	DestIP     string `json:"dest_ip" gorm:"size:45;index;not null"`
	SourcePort int    `json:"source_port" gorm:"index"`
	DestPort   int    `json:"dest_port" gorm:"index"`
	Protocol   string `json:"protocol" gorm:"size:10;index;not null"`
	Size       int    `json:"size" gorm:"not null"`

	// Optional fields
	Timestamp time.Time `json:"timestamp" gorm:"index"`
	Interface string    `json:"interface" gorm:"size:20"`
}

// PacketStats for helper struct

type PacketStats struct {
	TotalPackets   int64            `json:"total_packets`
	TotalSize      int64            `json:"total_size"`
	ProcotolCounts map[string]int64 `json:"protocol_counts"`
	TopIPS         []IPCount        `json:"top_ips"`
	TopPorts       []PortCount      `json:"top_ports"`
	LastHour       int64            `json:"last_hour"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

type PortCount struct {
	Port  int   `json:"port"`
	Count int64 `json:"count"`
}

func (Packet) TableName() string {
	return "packets"
}

func (p *Packet) IsHTTP() bool {
	return p.SourcePort == 80 || p.DestPort == 80 ||
		p.SourcePort == 443 || p.DestPort == 443
}

func (p *Packet) IsSSH() bool {
	return p.SourcePort == 22 || p.DestPort == 22
}

func (p *Packet) IsDNS() bool {
	return p.SourcePort == 53 || p.DestPort == 53
}

func (p *Packet) GetDirection(localIPS []string) string {
	for _, ip := range localIPS {
		if p.SourceIP == ip {
			return "outbound"
		}
		if p.DestIP == ip {
			return "inbound"
		}
	}
	return "unknown"
}
