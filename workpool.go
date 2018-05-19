package goaway3

import (
	"log"
	"time"
	"sync"
	"runtime"
	"sync/atomic"

	"github.com/AkihiroSuda/go-netfilter-queue"
)

//stolen from: https://github.com/valyala/fasthttp/blob/master/workerpool.go
//stolen from: https://github.com/valyala/fasthttp/blob/master/coarseTime.go
// this system uses a slightly tweaked version of the workerpool from fasthttp to handle and process
// incoming packets from NetFilterQueue as fast as possible

/* Variables */

type funcCache struct {
	Verdict netfilter.Verdict
	Err error
}

//timeStore : temporary store for time.Time in truncated form to allow for fast access / usage
var timeStore atomic.Value

// workerPool serves incoming connections via a pool of workers
// in FILO order, i.e. the most recently stopped worker will serve the next
// incoming connection.
// Such a scheme keeps CPU caches hot (in theory).
type workerPool struct {
	// Function for serving server connections.
	// It must leave c unclosed.
	WorkerFunc func(netfilter.NFPacket, *funcCache)
	MaxWorkersCount       int
	LogAllErrors          bool
	MaxIdleWorkerDuration time.Duration
	Logger                *log.Logger

	lock           sync.Mutex
	workersCount   int
	mustStop       bool
	ready          []*workerChan
	stopCh         chan struct{}
	workerChanPool sync.Pool
}

//workerChan : contains channel to handle given packets along with expiration timer
type workerChan struct {
	lastUseTime time.Time
	ch          chan netfilter.NFPacket
}

var workerChanCap = func() int {
	// Use blocking workerChan if GOMAXPROCS=1.
	// This immediately switches Serve to WorkerFunc, which results
	// in higher performance (under go1.5 at least).
	if runtime.GOMAXPROCS(0) == 1 {
		return 0
	}

	// Use non-blocking workerChan if GOMAXPROCS>1,
	// since otherwise the Serve caller (Acceptor) may lag accepting
	// new connections if WorkerFunc is CPU-bound.
	return 1
}()

/* Functions */

//CoarseTimeNow : return time truncated to seconds which
// is faster than using non-truncated version
func CoarseTimeNow() time.Time {
	tp := timeStore.Load().(*time.Time)
	return *tp
}

/* Init */
func init() {
	t := time.Now().Truncate(time.Second)
	timeStore.Store(&t)
	go func() {
		for {
			time.Sleep(time.Second)
			t := time.Now().Truncate(time.Second)
			timeStore.Store(&t)
		}
	}()
}

/* Methods */

//(*workerPool).Start : start worker-pool
func (wp *workerPool) Start() {
	if wp.stopCh != nil {
		panic("BUG: workerPool already started")
	}
	wp.stopCh = make(chan struct{})
	stopCh := wp.stopCh
	go func() {
		var scratch []*workerChan
		for {
			wp.clean(&scratch)
			select {
			case <-stopCh:
				return
			default:
				time.Sleep(wp.getMaxIdleWorkerDuration())
			}
		}
	}()
}

//(*workerPool).Stop : stop worker-pool
func (wp *workerPool) Stop() {
	if wp.stopCh == nil {
		panic("BUG: workerPool wasn't started")
	}
	close(wp.stopCh)
	wp.stopCh = nil

	// Stop all the workers waiting for incoming connections.
	// Do not wait for busy workers - they will stop after
	// serving the connection and noticing wp.mustStop = true.
	wp.lock.Lock()
	ready := wp.ready
	wp.Logger.Printf("DBUG: stopping all workers!")
	for i, ch := range ready {
		ch.ch <- netfilter.NFPacket{Packet: nil}
		ready[i] = nil
	}
	wp.ready = ready[:0]
	wp.mustStop = true
	wp.lock.Unlock()
}

//(*workerPool).getMaxIdleWorkerDuration : return variable with exception
func (wp *workerPool) getMaxIdleWorkerDuration() time.Duration {
	if wp.MaxIdleWorkerDuration <= 0 {
		return 10 * time.Second
	}
	return wp.MaxIdleWorkerDuration
}

//(*workerPool).clean : remove inactive workers
func (wp *workerPool) clean(scratch *[]*workerChan) {
	maxIdleWorkerDuration := wp.getMaxIdleWorkerDuration()

	// Clean least recently used workers if they didn't serve connections
	// for more than maxIdleWorkerDuration.
	currentTime := time.Now()

	wp.lock.Lock()
	ready := wp.ready
	n := len(ready)
	i := 0
	for i < n && currentTime.Sub(ready[i].lastUseTime) > maxIdleWorkerDuration {
		i++
	}
	*scratch = append((*scratch)[:0], ready[:i]...)
	if i > 0 {
		m := copy(ready, ready[i:])
		for i = m; i < n; i++ {
			ready[i] = nil
		}
		wp.ready = ready[:m]
	}
	wp.lock.Unlock()

	// Notify obsolete workers to stop.
	// This notification must be outside the wp.lock, since ch.ch
	// may be blocking and may consume a lot of time if many workers
	// are located on non-local CPUs.
	tmp := *scratch
	for i, ch := range tmp {
		ch.ch <- netfilter.NFPacket{Packet: nil}
		tmp[i] = nil
		wp.Logger.Printf("DBUG: attempting to clean worker!")
	}
}

//(*workerPool).Serve : pass connection to workerPool to handle
func (wp *workerPool) Serve(p netfilter.NFPacket) bool {
	ch := wp.getCh()
	if ch == nil {
		return false
	}
	ch.ch <- p
	return true
}

//(*workerPool).getCh : return available channel to pass packet for worker pool to handle
func (wp *workerPool) getCh() *workerChan {
	var ch *workerChan
	createWorker := false

	wp.lock.Lock()
	ready := wp.ready
	n := len(ready) - 1
	if n < 0 {
		if wp.workersCount < wp.MaxWorkersCount {
			createWorker = true
			wp.workersCount++
		}
	} else {
		ch = ready[n]
		ready[n] = nil
		wp.ready = ready[:n]
	}
	wp.lock.Unlock()

	if ch == nil {
		if !createWorker {
			return nil
		}
		vch := wp.workerChanPool.Get()
		if vch == nil {
			vch = &workerChan{
				ch: make(chan netfilter.NFPacket, workerChanCap),
			}
		}
		ch = vch.(*workerChan)
		go func() {
			wp.workerFunc(ch)
			wp.workerChanPool.Put(vch)
		}()
	}
	return ch
}

//(*workerPool).release : allow channel to be used among another worker
func (wp *workerPool) release(ch *workerChan) bool {
	ch.lastUseTime = CoarseTimeNow()
	wp.lock.Lock()
	if wp.mustStop {
		wp.lock.Unlock()
		return false
	}
	wp.ready = append(wp.ready, ch)
	wp.lock.Unlock()
	return true
}

//(*workerPool).workerFunc : worker function used to handle incoming connections via channels
func (wp *workerPool) workerFunc(ch *workerChan) {
	var p netfilter.NFPacket
	var cache = new(funcCache)
	for p = range ch.ch {
		if p.Packet == nil {
			break
		}
		if wp.WorkerFunc(p, cache); cache.Err != nil {
			if wp.LogAllErrors {
				wp.Logger.Printf("error when handling packet: %s", cache.Err)
			}
		}
		if !wp.release(ch) {
			break
		}
	}
	wp.lock.Lock()
	wp.workersCount--
	wp.lock.Unlock()
	wp.Logger.Printf("DBUG: Worker Exited!")
}