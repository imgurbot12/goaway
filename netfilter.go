package goaway2

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/***Variables***/

type NetfilterQueue struct {
	// Set Variables
	Handler    func(*RBKV, *PacketData) netfilter.Verdict
	QueueNum   uint16
	MaxWorkers int

	// queue handler objects
	nfq      *netfilter.NFQueue
	pktQueue <-chan netfilter.NFPacket

	// worker/class handler objects
	started bool
	wg      sync.WaitGroup
}

/***Methods***/

//(*NetfilterQueue).Start : spawn nfq instance and start collecting packets
func (queue *NetfilterQueue) Start() {
	// check if already started
	if queue.started {
		log.Fatalf("NFQueue %d ALREADY STARTED!\n", queue.QueueNum)
	}
	// spawn netfilter queue instance and start collecting packets
	var err error
	queue.nfq, err = netfilter.NewNFQueue(queue.QueueNum, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("NFQueue %d Error: %s\n", queue.QueueNum, err.Error())
	}
	log.Printf("NFQueue: %d Initialized! Starting Workers...\n", queue.QueueNum)
	// set packet queue and started boolean
	queue.pktQueue = queue.nfq.GetPackets()
	queue.started = true
	// start max number of workers
	for i := 0; i < queue.MaxWorkers; i++ {
		go queue.worker()
		queue.wg.Add(1)
	}
	log.Println("Workers Started!")
}

//(*NetfilterQueue).Wait : wait for threads to finish FOREVER!!! (A really long time)
func (queue *NetfilterQueue) Wait() {
	queue.wg.Wait()
}

//(*NetfilterQueue).Stop : close nfq instance and stop collecting packets
func (queue *NetfilterQueue) Stop() {
	// check if not started
	if !queue.started {
		log.Fatalf("NFQueue %d NEVER STARTED!\n", queue.QueueNum)
	}
	// close queue instance
	queue.nfq.Close()
	// close packet queue and set started boolean
	queue.pktQueue = nil
	queue.started = false
}

func (queue *NetfilterQueue) Run() {
	// start netfilter queue instance
	queue.Start()
	// handle interupts
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			log.Fatalf("Captured Signal: %v! Cleaning up...", sig)
			queue.Stop()
		}
	}()
	// wait possibly forever
	queue.Wait()
}

//(*NetfilterQueue).parsePacket : parse gopacket and return collected packet data
func (queue *NetfilterQueue) parsePacket(packetin gopacket.Packet, packetout *PacketData) {
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

//(*NetfilterQueue).worker : worker instance used to set the verdict for queued packets
func (queue *NetfilterQueue) worker() {
	// defer waitgroup completion
	defer queue.wg.Done()
	// init variables for packet handling
	var (
		nfqPacket  netfilter.NFPacket                   //Reused netfilter packet object
		dataPacket PacketData                           //Reused parsed packet data as struct
		redblackkv *RBKV              = NewRedBlackKV() //Reused key/value pair for red black tree caches
	)
	// loop while running forever
	for queue.started {
		// collect verdict packet from netfilerqueu
		nfqPacket = <-queue.pktQueue
		// parse packet for required information
		queue.parsePacket(nfqPacket.Packet, &dataPacket)
		// complete logic go get verfict on packet and set verdict
		nfqPacket.SetVerdict(
			queue.Handler(redblackkv, &dataPacket),
		)
	}
}
