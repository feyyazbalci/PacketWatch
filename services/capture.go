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
	db        *gorm.DB
	handle    *pcap.Handle
	isRunning bool
	stopChan  chan bool

	PacketCount int64
	StartTime   time.Time
}

func NewCaptureService(db *gorm.DB) *CaptureService {
	return &CaptureService{
		db:       db,
		stopChan: make(chan bool),
	}
}

func (cs *CaptureService) Start() error {
	if cs.isRunning {
		return fmt.Errorf("Capture service is already running")
	}

	if err := cs.openInterface(); err != nil {
		return fmt.Errorf("interface open error: %w", err)
	}

	cs.isRunning = true
	cs.StartTime = time.Now()
	cs.PacketCount = 0

	log.Println("Capture service started")

	go cs.capturePackets()
	return nil
}

func (cs *CaptureService) Stop() {
	if !cs.isRunning {
		return
	}

	cs.isRunning = false
	cs.stopChan <- true

	if cs.handle != nil {
		cs.handle.Close()
		cs.handle = nil
	}

	log.Println("Capture service stopped")
}

func (cs *CaptureService) openInterface() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("Could not find devices: %w", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("No network devices found")
	}

	var deviceName string
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			deviceName = device.AppName
			break
		}
	}

	if deviceName == "" {
		deviceName = "any"
	}

	log.Printf("Kullanılan interface: %s", deviceName)

	// open PCAP handle

	handle, err := pcap.OpenLive(
		deviceName,
		1600,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return fmt.Errorf("pcap open error: %w", err)
	}

	cs.handle = handle

	err = cs.handle.SetBPFFilter("tcp or udp or ICMP")

	if err != nil {
		log.Printf("BPF filter error: %v", err)
	}

	return nil
}

func (cs *CaptureService) capturePackets() {
	defer func() {
		cs.isRunning = false
		if cs.handle != nil {
			cs.handle.Close()
		}
	}()

	packetSource := gopacket.NewPacketSource(cs.handle, cs.handle.LinkType())

	log.Println("Packet capture loop started")

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			cs.processPacket(packet)
			cs.PacketCount++

		case <-cs.stopChan:
			log.Println("Stopping packet capture loop")
			return
		}
	}
}

func (cs *CaptureService) processPacket(packet gopacket.Packet) {
	parsedPacket := cs.parsePacket(packet)

	if parsedPacket != nil {
		return
	}

	if err := cs.db.Create(parsedPacket).Error; err != nil {
		log.Printf("Failed to save packet: %v", err)
		return
	}

	if cs.PacketCount%100 == 0 {
		log.Printf("📦 %d packet processed", cs.PacketCount)
	}
}

func (cs *CaptureService) parsePacket(packet gopacket.Packet) *models.Packet {
	result := &models.Packet{
		Timestamp: packet.Metadata().Timestamp,
		Size:      packet.Metadata().Length,
		Interface: "captured", // We can add the actual interface name later.
	}

	// Find IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	result.SourceIP = ip.SrcIP.String()
	result.DestIP = ip.DstIP.String()

	// Find transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		result.Protocol = "TCP"
		result.SourcePort = int(tcp.SrcPort)
		result.DestPort = int(tcp.DstPort)

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		result.Protocol = "UDP"
		result.SourcePort = int(udp.SrcPort)
		result.DestPort = int(udp.DstPort)

	} else {
		result.Protocol = ip.Protocol.String()
		result.SourcePort = 0
		result.DestPort = 0
	}

	return result
}

// GetStats returns current capture statistics
func (cs *CaptureService) GetStats() map[string]interface{} {
	status := map[string]interface{}{
		"running":      cs.isRunning,
		"packet_count": cs.PacketCount,
		"mode":         "real_capture",
	}

	if cs.isRunning {
		status["uptime"] = time.Since(cs.StartTime).String()
		status["packets_per_second"] = float64(cs.PacketCount) / time.Since(cs.StartTime).Seconds()
	}

	return status
}

func (cs *CaptureService) IsRunning() bool {
	return cs.isRunning
}
