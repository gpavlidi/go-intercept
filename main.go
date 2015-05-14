package main

import (
	"flag"
	"github.com/gpavlidi/go-intercept/interceptor"
	"log"
	"os"
	"path"
)

var iface = flag.String("i", "en0", "Interface to sniff packets from")
var filter = flag.String("f", "tcp and port 80", "BPF filter for pcap")
var verbose = flag.Bool("v", false, "Show debug information")
var snaplen = 1600 //max size to read for each packet

func main() {
	flag.Usage = func() {
		log.Printf("Usage of %s:\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	icpr := interceptor.Interceptor{Iface: *iface, Filter: *filter, Snaplen: snaplen, Verbose: *verbose}

	log.Println(&icpr)

	icpr.Run()

}
