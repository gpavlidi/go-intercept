package interceptor

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"time"
)

type Interceptor struct {
	Iface, Filter string
	Snaplen       int
	Verbose       bool

	handle                              *pcap.Handle
	requestAssembler, responseAssembler *tcpassembly.Assembler
	packets                             chan gopacket.Packet
}

func (icpr *Interceptor) String() string {
	return fmt.Sprintf("{iface:%s, filter:%s, snaplen: %v, verbose:%v}", icpr.Iface, icpr.Filter, icpr.Snaplen, icpr.Verbose)
}

func (icpr *Interceptor) startListening() {
	var err error

	// check if iface is valid
	_, err = FindDevByName(icpr.Iface)
	if err != nil {
		log.Fatal("Interface", icpr.Iface, "does not exist!")
	}

	// open Interface in Promiscuous mode
	icpr.handle, err = pcap.OpenLive(icpr.Iface, int32(icpr.Snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// pass filter to reject undesired packets
	if err := icpr.handle.SetBPFFilter(icpr.Filter); err != nil {
		log.Fatal(err)
	}

	// Set up assemblies
	requestStreamFactory := &httpStreamFactory{requestParser: true}
	requestStreamPool := tcpassembly.NewStreamPool(requestStreamFactory)
	icpr.requestAssembler = tcpassembly.NewAssembler(requestStreamPool)
	responseStreamFactory := &httpStreamFactory{requestParser: false}
	responseStreamPool := tcpassembly.NewStreamPool(responseStreamFactory)
	icpr.responseAssembler = tcpassembly.NewAssembler(responseStreamPool)

	// Set packet source
	packetSource := gopacket.NewPacketSource(icpr.handle, icpr.handle.LinkType())
	icpr.packets = packetSource.Packets()
}

func (icpr *Interceptor) Cleanup() {
	if icpr.handle != nil {
		icpr.handle.Close()
	}
}

func (icpr *Interceptor) processPacket(packet gopacket.Packet) error {
	// A nil packet indicates the end of a pcap file.
	if packet == nil {
		return errors.New("EOF")
	}

	// ignore spurious packets
	if !(packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP) {
		if icpr.Verbose {
			log.Println(packet)
		}
		tcp := packet.TransportLayer().(*layers.TCP)
		icpr.requestAssembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		icpr.responseAssembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
	return nil
}

func (icpr *Interceptor) Run() {
	var err error
	defer icpr.Cleanup()

	icpr.startListening()

	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-icpr.packets:
			err = icpr.processPacket(packet)
			if err != nil {
				return
			}
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			icpr.requestAssembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
			icpr.responseAssembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

}

// FindDevByName parses all devices and returns the one
// with a name that matches the passed string.
func FindDevByName(name string) (pcap.Interface, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}

	var dev pcap.Interface
	for _, v := range ifs {
		if v.Name == name {
			return v, err
		}
	}

	return pcap.Interface{}, errors.New(fmt.Sprint("Cant find device", dev))
}
