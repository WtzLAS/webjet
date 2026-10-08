// raknet-lan plays one Minecraft Bedrock instance on a LAN, for
// docker/raknet-storm-test.sh: a RakNet server answering discovery pings
// (go-raknet, the library Bedrock proxies use) and a client on the
// Friends tab that broadcasts RakNet unconnected pings to
// 255.255.255.255:19132 and lists the servers that answer.
//
//	raknet-lan -name g-1 -bind 10.7.0.11 -rate 1 -status /tmp/rak.json
//	           [-connect] [-relay] [-mutate]
//
// -connect opens a RakNet connection to every server found and exchanges
// a message a second on it. -relay rebroadcasts every discovery ping it
// hears from another host (a naive "LAN bridge", the classic way to make
// a broadcast loop); -mutate changes each relayed ping, so it is no
// longer an exact echo. The status file has one "key value" line per
// field (worlds and dial errors joined by "|"), rewritten every 200 ms.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sandertv/go-raknet"
)

const port = 19132

var magic = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

type status struct {
	Name      string            `json:"name"`
	PingsSent int64             `json:"pings_sent"`
	Pongs     int64             `json:"pongs"`
	Servers   map[string]string `json:"servers"`
	Connected []string          `json:"connected"`
	Echoes    int64             `json:"echoes"`
	DialErrs  map[string]string `json:"dial_errors"`
	Relayed   int64             `json:"relayed"`
}

// text renders the status for shell scripts: `key value` lines.
func (s *status) text() []byte {
	worlds := make([]string, 0, len(s.Servers))
	for _, w := range s.Servers {
		worlds = append(worlds, w)
	}
	sort.Strings(worlds)
	errs := make([]string, 0, len(s.DialErrs))
	for ip, e := range s.DialErrs {
		errs = append(errs, ip+": "+e)
	}
	sort.Strings(errs)
	var b strings.Builder
	fmt.Fprintf(&b, "name %s\n", s.Name)
	fmt.Fprintf(&b, "pings_sent %d\npongs %d\nservers %d\nconnected %d\n", s.PingsSent, s.Pongs, len(s.Servers), len(s.Connected))
	fmt.Fprintf(&b, "echoes %d\nrelayed %d\ndial_errors %d\n", s.Echoes, s.Relayed, len(s.DialErrs))
	fmt.Fprintf(&b, "worlds %s\nerrors %s\n", strings.Join(worlds, "|"), strings.Join(errs, "|"))
	return []byte(b.String())
}

var (
	mu      sync.Mutex
	st      status
	stopped bool // no more sends counted after SIGTERM
)

// reuse lets the RakNet server and the relay share port 19132 (both get
// every broadcast) and lets sockets send broadcasts.
func control(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		for _, o := range []int{syscall.SO_REUSEADDR, syscall.SO_BROADCAST} {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, o, 1); e != nil {
				serr = e
			}
		}
	})
	if err != nil {
		return err
	}
	return serr
}

type upstream struct{}

func (upstream) ListenPacket(network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{Control: control}).ListenPacket(context.Background(), network, address)
}

func main() {
	name := flag.String("name", "", "this player's name")
	bind := flag.String("bind", "", "overlay address the client sends from")
	rate := flag.Float64("rate", 1, "discovery pings per second")
	out := flag.String("status", "/tmp/rak.json", "status file")
	connect := flag.Bool("connect", false, "connect to every server found")
	relay := flag.Bool("relay", false, "rebroadcast discovery pings heard from other hosts")
	mutate := flag.Bool("mutate", false, "with -relay: change each relayed ping")
	noClient := flag.Bool("no-client", false, "server (and relay) only")
	flag.Parse()
	st = status{Name: *name, Servers: map[string]string{}, DialErrs: map[string]string{}}

	// The server: a LAN world others see in their Friends tab.
	guid := rand.Int64()
	l, err := raknet.ListenConfig{UpstreamPacketListener: upstream{}}.Listen(fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal(err)
	}
	l.PongData([]byte(fmt.Sprintf("MCPE;%s's world;844;1.21.111;1;8;%d;Bedrock level;Survival;1;%d;%d;0;", *name, guid, port, port+1)))
	go serve(l)

	if *relay {
		go runRelay(*bind, *mutate)
	}
	if !*noClient {
		go client(*bind, *rate, *connect)
	}
	write := func() {
		mu.Lock()
		b := st.text()
		mu.Unlock()
		_ = os.WriteFile(*out+".tmp", b, 0o644)
		_ = os.Rename(*out+".tmp", *out)
	}
	// On SIGTERM the final counts are written before exiting.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-tick.C:
			write()
		case <-stop:
			mu.Lock()
			stopped = true
			mu.Unlock()
			write()
			os.Exit(0)
		}
	}
}

// serve echoes whatever connected players send.
func serve(l *raknet.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
	}
}

func broadcastSocket(bind string) *net.UDPConn {
	pc, err := (&net.ListenConfig{Control: control}).ListenPacket(context.Background(), "udp4", bind+":0")
	if err != nil {
		log.Fatal(err)
	}
	return pc.(*net.UDPConn)
}

// client broadcasts discovery pings and collects pongs, as the Friends
// tab does; with connect, it joins every world it finds.
func client(bind string, rate float64, connect bool) {
	s := broadcastSocket(bind)
	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: port}
	clientGUID := rand.Int64()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := s.ReadFromUDP(buf)
			if err != nil {
				log.Fatal(err)
			}
			b := buf[:n]
			// ID_UNCONNECTED_PONG: id, time(8), server guid(8), magic(16),
			// len(2), "MCPE;…".
			if n < 35 || b[0] != 0x1c || string(b[17:33]) != string(magic) {
				continue
			}
			if from.IP.String() == bind {
				continue // our own world, answered locally
			}
			l := int(binary.BigEndian.Uint16(b[33:35]))
			motd := ""
			if 35+l <= n {
				motd = string(b[35 : 35+l])
			}
			world := strings.Split(motd, ";")
			ip := from.IP.String()
			mu.Lock()
			st.Pongs++
			_, known := st.Servers[ip]
			if len(world) > 1 {
				st.Servers[ip] = world[1]
			}
			mu.Unlock()
			if connect && !known {
				go play(bind, ip)
			}
		}
	}()
	gap := time.Duration(float64(time.Second) / rate)
	next := time.Now()
	for {
		// ID_UNCONNECTED_PING: id, time(8), magic(16), client guid(8).
		p := make([]byte, 33)
		p[0] = 0x01
		binary.BigEndian.PutUint64(p[1:], uint64(time.Now().UnixMilli()))
		copy(p[9:], magic)
		binary.BigEndian.PutUint64(p[25:], uint64(clientGUID))
		mu.Lock()
		if stopped {
			mu.Unlock()
			return
		}
		if _, err := s.WriteToUDP(p, bcast); err == nil {
			st.PingsSent++
		}
		mu.Unlock()
		next = next.Add(gap)
		time.Sleep(time.Until(next))
	}
}

// play joins a world over RakNet (MTU discovery, connection handshake)
// and exchanges a message a second.
func play(bind, ip string) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := raknet.Dialer{UpstreamDialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(bind)}}}
	var c *raknet.Conn
	var err error
	for try := 0; try < 3; try++ {
		if c, err = d.DialTimeout(addr, 10*time.Second); err == nil {
			break
		}
	}
	if err != nil {
		mu.Lock()
		st.DialErrs[ip] = err.Error()
		mu.Unlock()
		return
	}
	mu.Lock()
	st.Connected = append(st.Connected, ip)
	delete(st.DialErrs, ip)
	mu.Unlock()
	buf := make([]byte, 1500)
	for {
		msg := []byte(fmt.Sprintf("tick from %s %d", bind, time.Now().UnixNano()))
		if _, err := c.Write(msg); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err == nil && string(buf[:n]) == string(msg) {
			mu.Lock()
			st.Echoes++
			mu.Unlock()
		}
		time.Sleep(time.Second)
	}
}

// runRelay rebroadcasts every discovery ping heard from another host.
func runRelay(bind string, mutate bool) {
	in, err := (&net.ListenConfig{Control: control}).ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal(err)
	}
	s := broadcastSocket(bind)
	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: port}
	buf := make([]byte, 1500)
	var n64 uint64
	for {
		n, from, err := in.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		if n < 33 || buf[0] != 0x01 || from.(*net.UDPAddr).IP.String() == bind {
			continue
		}
		p := append([]byte(nil), buf[:n]...)
		if mutate {
			n64++
			binary.BigEndian.PutUint64(p[1:], n64) // a new "ping time"
		}
		if _, err := s.WriteToUDP(p, bcast); err == nil {
			mu.Lock()
			st.Relayed++
			mu.Unlock()
		}
	}
}
