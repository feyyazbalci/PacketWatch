package models

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Packet - Yakalanan network paketlerini temsil eder
type Packet struct {
	// Temel alanlar
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Packet meta bilgileri
	Timestamp time.Time `gorm:"index;not null" json:"timestamp"` // Paketin yakalandığı zaman
	Size      int       `gorm:"not null" json:"size"`            // Packet boyutu (bytes)
	Interface string    `gorm:"size:50;index" json:"interface"`  // Hangi network interface'den yakalandı

	// Network Layer (IP) bilgileri
	SourceIP      string `gorm:"size:45;index;not null" json:"source_ip"`      // Kaynak IP (IPv4/IPv6)
	DestinationIP string `gorm:"size:45;index;not null" json:"destination_ip"` // Hedef IP
	IPVersion     int    `gorm:"not null" json:"ip_version"`                   // 4 veya 6
	TTL           int    `json:"ttl,omitempty"`                                // Time To Live
	IPFlags       string `gorm:"size:10" json:"ip_flags,omitempty"`            // IP flags (DF, MF, etc.)

	// Transport Layer bilgileri
	Protocol        string `gorm:"size:10;index;not null" json:"protocol"`  // TCP, UDP, ICMP, etc.
	SourcePort      *int   `gorm:"index" json:"source_port,omitempty"`      // Kaynak port (TCP/UDP için)
	DestinationPort *int   `gorm:"index" json:"destination_port,omitempty"` // Hedef port (TCP/UDP için)

	// TCP özel alanları
	TCPFlags  string  `gorm:"size:20" json:"tcp_flags,omitempty"` // SYN, ACK, FIN, RST, etc.
	TCPSeq    *uint32 `json:"tcp_seq,omitempty"`                  // TCP Sequence number
	TCPAck    *uint32 `json:"tcp_ack,omitempty"`                  // TCP Acknowledgment number
	TCPWindow *uint16 `json:"tcp_window,omitempty"`               // TCP Window size

	// Payload bilgileri
	PayloadSize int    `json:"payload_size"`                                // Payload boyutu
	PayloadHash string `gorm:"size:64;index" json:"payload_hash,omitempty"` // Payload'ın SHA256 hash'i

	// Ham veri (dikkatli kullan - büyük olabilir)
	RawPacket []byte `json:"-"` // Raw packet data (JSON'da gösterme)

	// Analiz sonuçları (JSON olarak saklanır)
	Metadata JSON `json:"metadata,omitempty"` // Ek analiz verileri
}

// JSON - PostgreSQL JSON field için custom type
type JSON map[string]interface{}

// Value - GORM için JSON serialize
func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan - GORM için JSON deserialize
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, j)
}

// PacketStats - Packet istatistikleri için yardımcı struct
type PacketStats struct {
	TotalPackets   int64            `json:"total_packets"`
	TotalSize      int64            `json:"total_size"`
	ProtocolCounts map[string]int64 `json:"protocol_counts"`
	TopSourceIPs   []IPCount        `json:"top_source_ips"`
	TopDestIPs     []IPCount        `json:"top_dest_ips"`
	TopPorts       []PortCount      `json:"top_ports"`
	TimeRange      TimeRange        `json:"time_range"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

type PortCount struct {
	Port  int   `json:"port"`
	Count int64 `json:"count"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Connection - TCP connection tracking için
type Connection struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Connection identifier (unique)
	SourceIP        string `gorm:"size:45;not null" json:"source_ip"`
	DestinationIP   string `gorm:"size:45;not null" json:"destination_ip"`
	SourcePort      int    `gorm:"not null" json:"source_port"`
	DestinationPort int    `gorm:"not null" json:"destination_port"`
	Protocol        string `gorm:"size:10;not null" json:"protocol"`

	// Connection state
	State     string     `gorm:"size:20;default:'UNKNOWN'" json:"state"` // ESTABLISHED, TIME_WAIT, etc.
	StartTime time.Time  `gorm:"not null" json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  *int64     `json:"duration,omitempty"` // milliseconds

	// Traffic statistics
	PacketCount int64 `gorm:"default:0" json:"packet_count"`
	BytesOut    int64 `gorm:"default:0" json:"bytes_out"` // Source -> Destination
	BytesIn     int64 `gorm:"default:0" json:"bytes_in"`  // Destination -> Source

	// Relationships
	Packets []Packet `gorm:"constraint:OnDelete:CASCADE" json:"-"` // Bu connection'a ait paketler
}

func (Packet) TableName() string {
	return "packets"
}

func (Connection) TableName() string {
	return "connections"
}

// GORM Hooks - Veritabanı işlemleri öncesi/sonrası
func (p *Packet) BeforeCreate(tx *gorm.DB) error {
	// Payload hash'i otomatik hesapla
	if len(p.RawPacket) > 0 && p.PayloadHash == "" {
		hash := sha256.Sum256(p.RawPacket)
		p.PayloadHash = fmt.Sprintf("%x", hash)
	}
	return nil
}

// Helper methods
func (p *Packet) IsWeb() bool {
	webPorts := []int{80, 443}
	for _, port := range webPorts {
		if p.SourcePort != nil && *p.SourcePort == port {
			return true
		}
		if p.DestinationPort != nil && *p.DestinationPort == port {
			return true
		}
	}
	return false
}

func (p *Packet) IsSSH() bool {
	return (p.SourcePort != nil && *p.SourcePort == 22) ||
		(p.DestinationPort != nil && *p.DestinationPort == 22)
}

func (p *Packet) IsDNS() bool {
	return (p.SourcePort != nil && *p.SourcePort == 53) ||
		(p.DestinationPort != nil && *p.DestinationPort == 53)
}

func (c *Connection) ConnectionID() string {
	return fmt.Sprintf("%s:%d-%s:%d-%s",
		c.SourceIP, c.SourcePort,
		c.DestinationIP, c.DestinationPort,
		c.Protocol)
}
