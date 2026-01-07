package main
import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "\n")
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		return scanner.Text()
	}
	return "No banner detected"
}

func main() {
	target := flag.String("t", "", "Target IP address")
	workers := flag.Int("w", 100, "Number of concurrent workers")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Mantis Engine v1.0 - Fast Scanner & Banner Grabber\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *target == "" {
		flag.Usage()
		return
	}

	ports := make(chan int, 1000)
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				address := fmt.Sprintf("%s:%d", *target, p)
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err == nil {
					banner := grabBanner(conn)
					fmt.Printf("[+] PORT %d: %s\n", p, banner)
					conn.Close()
				}
			}
		}()
	}

	for i := 1; i <= 1024; i++ { ports <- i }
	close(ports)
	wg.Wait()
}
