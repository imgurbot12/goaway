package goaway2

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
)

/***Variables***/

type NetFilterQueue struct {
	// Set Variables
	Handler      func(*log.Logger, *RBKV, *PacketData) netfilter.Verdict
	QueueNum     uint16
	LogAllErrors bool
	Logger       *log.Logger

	// queue handler objects
	nfq      *netfilter.NFQueue
	pktQueue <-chan netfilter.NFPacket
	wp       *workerPool
}

/***Methods***/

//(*NetFilterQueue).start : spawn nfq instance and start collecting packets
func (q *NetFilterQueue) start() {
	// check if already started
	if q.wp != nil {
		q.Logger.Fatalf("NFQueue %d ALREADY STARTED!\n", q.QueueNum)
	}
	// spawn netfilter queue instance and start collecting packets
	var err error
	q.nfq, err = netfilter.NewNFQueue(q.QueueNum, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("NFQueue %d Error: %s\n", q.QueueNum, err.Error())
	}
	q.Logger.Printf(`

   |\                     /)
 /\_\\__               (_//
|   '>\-'     _._       //')
 \ /' \\  _.-':::'-._  //
  '    \|'    :::    '|/  _____          ___                          
        |     :::     |  |  __ \        / _ \                         
        |.....:::.....|  | |  \/  ___  / /_\ \__      __  __ _  _   _ 
        |:::::::::::::|  | | __  / _ \ |  _  |\ \ /\ / / / _' || | | |
        |     :::     |  | |_\ \| (_) || | | | \ V  V / | (_| || |_| |
        \     :::     /   \____/ \___/ \_| |_/  \_/\_/   \__,_| \__, | 
         \    :::    /                                           __/ |
          '-. ::: .-'                                           |___/ 
           //':::'\\
          //   '   \\
         |/         \\

`)
	q.Logger.Printf("NFQueue: %d, Initalized!", q.QueueNum)
	q.Logger.Printf("Workers Starting... DONE!")
	// set packet queue and started boolean
	q.pktQueue = q.nfq.GetPackets()
	// spawn workerpool
	q.wp = &workerPool{
		WorkerFunc: q.handlePacket,
		MaxWorkersCount: 10 * 1024,
		LogAllErrors: q.LogAllErrors,
		Logger: q.Logger,
	}
	q.wp.Start()
}

//(*NetFilterQueue).stop : close nfq instance and stop collecting packets
func (q *NetFilterQueue) stop() {
	// check if not started
	if q.wp == nil {
		log.Fatalf("NFQueue %d NEVER STARTED!\n", q.QueueNum)
	}
	// close/stop everything
	q.nfq.Close()
	q.wp.Stop()
	q.pktQueue = nil
}

//(*NetFilterQueue).Run : run nfq indefinably and block until interrupt
func (q *NetFilterQueue) Run() {
	// start netfilter queue instance
	q.start()
	// handle interrupts
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			log.Fatalf("Captured Signal: %s! Cleaning up...", sig.String())
			q.stop()
		}
	}()
	// handle incoming packets
	var p netfilter.NFPacket
	for {
		p = <- q.pktQueue
		if !q.wp.Serve(p) {
			log.Println("worker error! serving connection failed!")
		}
	}
}

//(*NetFilterQueue).parsePacket : parse gopacket and return collected packet data
func (q *NetFilterQueue) parsePacket(packetin gopacket.Packet, packetout *PacketData) {
	//get src and dst ip from ipv4
	ipLayer := packetin.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		packetout.SrcIP = ip.SrcIP.String()
		packetout.DstIP = ip.DstIP.String()
		packetout.Protocol = ip.Protocol.String()
	}
	//get src and dst from tcp ports
	tcpLayer := packetin.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		packetout.SrcPort = int64(tcp.SrcPort)
		packetout.DstPort = int64(tcp.DstPort)
	}
}

//(*NetFilterQueue).worker : worker instance used to set the verdict for queued packets
func (q *NetFilterQueue) handlePacket(p netfilter.NFPacket) error {
	// init variables for packet handling
	var (
		dataPacket PacketData           //Reused parsed packet data as struct
		redBlackKV            = &RBKV{} //Reused key/value pair for red black tree caches
	)
	// parse packet for required information
	q.parsePacket(p.Packet, &dataPacket)
	// complete logic go get verdict on packet and set verdict
	p.SetVerdict(
		q.Handler(q.Logger, redBlackKV, &dataPacket),
	)
	return nil
}
