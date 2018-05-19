package goaway3

import (
	"os"
	"log"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
)

/* Variables */
type NetFilterQueue struct {
	Handler func(gopacket.Packet) (netfilter.Verdict, error)
	QueueNum uint16
	LogAllErrors bool
	Logger *log.Logger

	nfq *netfilter.NFQueue
	pktQ <-chan netfilter.NFPacket
	wp *workerPool
}

/* Methods */

//(*NetFilterQueue).handle : collect packet and pass verdict to handler
func (q *NetFilterQueue) handle(packet netfilter.NFPacket, cache *funcCache) {
	cache.Verdict, cache.Err = q.Handler(packet.Packet)
	packet.SetVerdict(cache.Verdict)
}

//(*NetFilterQueue).start : start NetFilter-Queue instance
func (q *NetFilterQueue) start() error {
	// check if already started
	if q.wp != nil {
		return fmt.Errorf("queue: %d already started", q.QueueNum)
	}
	// spawn NetFilter instance
	var err error
	q.nfq, err = netfilter.NewNFQueue(q.QueueNum, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		return fmt.Errorf("queue: %d init-error: %s", q.QueueNum, err.Error())
	}
	// initiate packet queue
	q.pktQ = q.nfq.GetPackets()
	// spawn work-pool
	q.wp = &workerPool{
		WorkerFunc: q.handle,
		MaxWorkersCount: 10 * 1024,
		LogAllErrors: q.LogAllErrors,
		Logger: q.Logger,
	}
	q.wp.Start()
	return nil
}

//(*NetFilterQueue).stop : stop all instances and reset objects
func (q *NetFilterQueue) stop() error {
	if q.wp == nil {
		return fmt.Errorf("queue: %d never started", q.QueueNum)
	}
	q.nfq.Close()
	q.wp.Stop()
	q.pktQ = nil
	q.wp = nil
	return nil
}

//(*NetFilterQueue).Run : run nfq indefinably and block until interrupt
func (q *NetFilterQueue) Run() {
	// start NetFilter-Queue instance
	q.start()
	// handle interrupts
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			q.Logger.Fatalf("Captured Signal: %s! Cleaning up...", sig.String())
			q.stop()
		}
	}()
	// handle incoming packets
	var p netfilter.NFPacket
	for {
		p = <- q.pktQ
		if !q.wp.Serve(p) {
			q.Logger.Println("worker error! serving connection failed!")
		}
	}
}
