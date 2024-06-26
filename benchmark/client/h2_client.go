package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"test/apphelper"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"test/http2"
)

type simulation struct {
	time           time.Duration
	lock           *sync.Mutex
	clients        []*http.Client
	backup         []*http.Client
	measureLatency bool
	logfile        *os.File
	clientIndex    uint32
	conn_mon       *ConnectionMonitor
	use_bk         bool
	add_timestamp  bool
	warmup         time.Time
	inflightreads  map[int64]map[string]string
}

var clientIndexg uint32

func (sim *simulation) GetClient(bkup bool) *http.Client {
	clientIndex := atomic.AddUint32(&clientIndexg, 1) % uint32(len(sim.clients))
	if bkup {
		return sim.backup[clientIndex]
	}
	return sim.clients[clientIndex]
}

func (sim * simulation) ClearBenchmarkRequests() (string, error) {
	req, err := http.NewRequest("POST", "https://www.webchannel.sandbox.google.com/dev/static/rpctransportbenchmark", nil)
	if err != nil {
		return  "", err
	}
	req.Header.Set("benchmarkreset", "true")

	resp, err := sim.GetClient(sim.use_bk).Do(req)
	if  (err != nil) {
		return  "", err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		return string(body), err
	} else {
		return "", errors.New("HTTP not OK")
	}
}

func (sim *simulation) writeResult(start time.Time, latency time.Duration, err error) {
	sim.lock.Lock()
	defer sim.lock.Unlock()
	if sim.logfile != nil {
		fmt.Fprintf(sim.logfile, "%d %d %v\n", start.UnixMilli(), latency.Microseconds(), err)
		return
	}
}

func (sim *simulation) UnaryCall(ctx context.Context, client *http.Client, req *http.Request) (time.Time, time.Duration, error) {
	timeStartReq := time.Now()
	if sim.add_timestamp && sim.warmup.Before(timeStartReq) {
		sim.conn_mon.AckExpected(timeStartReq.GoString())
	}
	timeStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		if sim.add_timestamp && sim.warmup.Before(timeStartReq) {
			sim.conn_mon.AckReceived(timeStartReq.GoString())
		}
		return timeStart, time.Since(timeStart), errors.New("client send failed")
	}
	defer resp.Body.Close()
	// Process the response.
	if sim.add_timestamp && sim.warmup.Before(timeStartReq) {
		sim.conn_mon.AckReceived(timeStartReq.GoString())
	}
	if resp.StatusCode == http.StatusOK {
		return timeStart, time.Since(timeStart), nil
	} else {
		return timeStart, time.Since(timeStart), errors.New("HTTP not OK")
	}
}

func (sim *simulation) HandleAck() {
	if sim.add_timestamp && sim.warmup.Before(time.Now()) {
		sim.conn_mon.DataReceived()
	}
}

func (sim *simulation) RetryReads() {
	req, err := http.NewRequest("POST", "https://www.webchannel.sandbox.google.com/dev/static/rpctransportbenchmark", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	var swg sync.WaitGroup
	for _, header := range sim.inflightreads {
		for key, value := range header {
			req.Header.Set(key, value)
		}
		data := make([]byte, 0)

		reader := bytes.NewReader(data)
		closer := ioutil.NopCloser(reader)

		readCloser := io.ReadCloser(closer)
		req.Body = readCloser

		swg.Add(1)
		go func() {
			var timeStart time.Time
			var timeDuration time.Duration
			timeStart, timeDuration, err = sim.UnaryCall(context.Background(), sim.GetClient(sim.use_bk), req)
			sim.writeResult(timeStart, timeDuration, err)
			swg.Done()
		}()
	}
	swg.Wait()

}
func (sim *simulation) handleRPC(rpc *apphelper.RPCParams, wg *sync.WaitGroup) {
	defer wg.Done()

	// Time to end simulation.
	timeEnd := time.Now().Add(sim.time)

	header := make(map[string]string)

	requestDist, err := apphelper.NewDistribution(rpc.Arrival)
	if err != nil {
		fmt.Printf("Could not get arrival time distribution %v", err)
		return
	}
	var sizeDist, timeDist, sendDist apphelper.Distribution

	switch rpc.Type {
	case "Unary":
		sizeDist, err = apphelper.NewDistribution(rpc.MessageSize)
		if err != nil {
			return
		}
		timeDist, err = apphelper.NewDistribution(rpc.ProcessingDelay)
		if err != nil {
			return
		}
		sendDist, err = apphelper.NewDistribution(rpc.SendSize)
		if err != nil {
			return
		}

	case "Stream":
		break
	default:
		fmt.Println("apphelperfind")
		return
	}

	// Create an HTTP request.
	req, err := http.NewRequest("POST", "https://www.webchannel.sandbox.google.com"+rpc.Path, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	header["Host"] = "www.webchannel.sandbox.google.com"

	var swg sync.WaitGroup
	for time.Now().Before(timeEnd) {
		if rpc.Type == "Unary" {
			size := uint32(sizeDist.Rand())
			header["replylength"] = fmt.Sprintf("%d", size)
			header["replytime"] = fmt.Sprintf("%d", uint64(timeDist.Rand()))
			reqTime := time.Now().UnixNano()
			header["requesttimestamp"] = fmt.Sprintf("%d",reqTime)
			// Add custom headers to the request.
			for key, value := range header {
				req.Header.Set(key, value)
			}
			data := make([]byte, int(sendDist.Rand()))

			if (len(data) == 0){
				//This is a read request. Save header
				sim.lock.Lock()
				sim.inflightreads[reqTime] = header
				sim.lock.Unlock()
			}
			reader := bytes.NewReader(data)
			closer := ioutil.NopCloser(reader)

			readCloser := io.ReadCloser(closer)
			req.Body = readCloser

			swg.Add(1)
			go func() {
				var timeStart time.Time
				var timeDuration time.Duration
				if sim.measureLatency {
					timeStart, timeDuration, err = sim.UnaryCall(context.Background(), sim.GetClient(sim.use_bk), req)
				} else {
					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rpc.Timeout)*time.Millisecond)
					defer cancel()
					timeStart, timeDuration, err = sim.UnaryCall(ctx, sim.GetClient(sim.use_bk), req)
				}
				sim.writeResult(timeStart, timeDuration, err)
				sim.lock.Lock()
				delete(sim.inflightreads,reqTime)
				sim.lock.Unlock()
				swg.Done()
			}()
		} else {
			fmt.Println("apphelperfind RPC")
			break
		}
		time.Sleep(time.Duration(requestDist.Rand()) * time.Millisecond)
	}
	swg.Wait()

}

func main() {
	cfg := flag.String("cfg", "", "Configuration file")
	log := flag.String("log", "/tmp/h2_client_log.txt", "logfile")
	qlog_loc := flag.String("qlog", "/tmp/qlog.txt", "quiclog")
	insecureSkipVerify := flag.Bool("insecure_skip_verify", false, "Disable certificate verification")
	flag.Parse()

	dat, err := os.ReadFile(*cfg)
	if err != nil {
		fmt.Println("File not found ", err)
		return
	}

	var data map[string]any
	if err = json.Unmarshal(dat, &data); err != nil {
		fmt.Printf("Error in Json.Unmarshal(%s): %s", string(dat), err)
		return
	}

	num_clients_p, ok := data["num_clients"].(float64)
	if !ok {
		fmt.Println("Invalid num_clients", data["num_clients"])
		return
	}

	num_clients := int(num_clients_p)

	client_type, ok := data["client_type"]
	if !ok {
		fmt.Println("Invalid client_type", data["client_type"])
		return
	}

	tlsConfig := &tls.Config{}
	if *insecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	var sim simulation

	_, bkok := data["backup_conn"]
	var main_dailer, bk_dailer *CustomDialer
	main_dailer, err = NewCustomDialer("ens4",30000, 31001)
	if err != nil {
		fmt.Println(err)
		return
	}
	if bkok {
		bk_dailer, err = NewCustomDialer("ens4",40000,40001)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	var transport, bktransport http.RoundTripper
	if client_type == "h2" {
		tr := &http2.Transport{
			TLSClientConfig: tlsConfig,
			RecvPkt:         sim.HandleAck,
		}

		tr.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := main_dailer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, cfg), nil
		}

		if bkok {
			bktransport = &http2.Transport{
				TLSClientConfig: tlsConfig,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					conn, err := bk_dailer.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					return tls.Client(conn, cfg), nil
				},
			}
		}
		transport = tr
	} else if client_type == "h3" {
		var qconf quic.Config
		qconf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			filename := fmt.Sprintf(*qlog_loc, connID)
			f, err := os.Create(filename)
			if err != nil {
				fmt.Println(err)
			}

			return qlog.NewConnectionTracer(io.WriteCloser(f), p, connID)
		}

		transport = &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QuicConfig:      &qconf,
		}
	}

	for i := 0; i < num_clients; i++ {
		// Create an HTTP client with the HTTP/2 Transport.
		sim.clients = append(sim.clients, &http.Client{
			Transport: transport,
		})
		if bkok {
			sim.backup = append(sim.backup, &http.Client{
				Transport: bktransport,
			})
		}
	}

	rpcInfo, found := data["rpcs"].([]any)
	if !found {
		fmt.Printf("Rpcs not found in %s", string(dat))
		return
	}

	str, _ := json.Marshal(rpcInfo)
	rpcs, err := apphelper.RPCFromJSON(string(str))
	if err != nil {
		fmt.Println("RPC creation error: ", err)
		return
	}

	testInfo, found := data["test-duration"]
	if !found {
		fmt.Printf("TestDuration not found in %s", string(dat))
		return
	}

	testDuration, ok := testInfo.(float64)
	if !ok {
		fmt.Printf("TestDuration not an integer, %v", testInfo)
		return
	}

	sim.time = time.Second * time.Duration(testDuration)
	sim.lock = &sync.Mutex{}
	sim.logfile, err = os.Create(*log)
	sim.use_bk = false
	sim.add_timestamp = bkok
	sim.warmup = time.Now().Add(30 * time.Second)
	sim.inflightreads = make(map[int64]map[string]string)
	if bkok {
		sim.conn_mon = NewConnectionMonitor("test", func() {
			if (sim.use_bk) {
				return
			}
			sim.lock.Lock()
			if sim.logfile != nil {
				fmt.Fprintf(sim.logfile, "Fault detected %v retries %d\n", time.Now().UnixMilli(), len(sim.inflightreads))
			}
			sim.lock.Unlock()
			sim.use_bk = true
			go sim.RetryReads()
		})
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer sim.logfile.Close()

	sim.measureLatency = true

	time.Sleep(time.Second)
	body, err :=  sim.ClearBenchmarkRequests ()
	if err != nil {
		fmt.Println (body)
	}
	var wg sync.WaitGroup
	for _, rpc := range rpcs {
		wg.Add(1)
		go sim.handleRPC(rpc, &wg)
	}
	wg.Wait()
	body, err =  sim.ClearBenchmarkRequests ()
	if err != nil {
		fmt.Println (body)
	}
}
