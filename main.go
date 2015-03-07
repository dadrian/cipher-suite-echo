package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/zmap/zgrab/ztools/zlog"
	"github.com/zmap/zgrab/ztools/ztls"
)

type Flags struct {
	CertificateChainPath string
	KeyPath              string
	LogFileName          string
	ListenAddress        string
	ErrorFileName        string
}

func (f *Flags) Validate() error {
	if f.CertificateChainPath == "" {
		return errors.New("Certificate not specified")
	}
	if f.KeyPath == "" {
		return errors.New("Key not specified")
	}
	return nil
}

var flags Flags

func init() {
	flag.StringVar(&flags.CertificateChainPath, "certificate", "", "Path to certificate chain (PEM encoded)")
	flag.StringVar(&flags.KeyPath, "key", "", "Path to key corresponding to certificate (PEM encoded, decrypted)")
	flag.StringVar(&flags.ListenAddress, "listen-address", "127.0.0.1:443", "ip:port to listen on")
	flag.StringVar(&flags.LogFileName, "log-file", "-", "defaults to stderr")
	flag.StringVar(&flags.ErrorFileName, "error-file", "errors.log", "Logs connection-level errors")
	flag.Parse()
}

type CipherList struct {
	Ciphers []ztls.CipherSuite `json:"ciphers"`
}

type HostLogEntry struct {
	Host     string             `json:"ip_address"`
	Time     string             `json:"time"`
	Ciphers  []ztls.CipherSuite `json:"ciphers,omitempty"`
	RawHello []byte             `json:"raw_hello,omitempty"`
	Request  string             `json:"request,omitempty"`
}

var logChan chan HostLogEntry

func ciphers(c *ztls.Conn) error {
	defer c.Close()
	t := time.Now()
	deadline := t.Add(time.Second * 30)
	c.SetDeadline(deadline)
	entry := HostLogEntry{}
	entry.Time = t.Format(time.RFC3339)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	entry.Host = host
	handshakeErr := c.Handshake()
	entry.Ciphers = c.ClientCiphers()
	entry.RawHello = c.ClientHelloRaw()
	if handshakeErr != nil {
		logChan <- entry
		return handshakeErr
	}
	cl := CipherList{}
	cl.Ciphers = entry.Ciphers
	buf := make([]byte, 1024)
	n, _ := c.Read(buf)
	entry.Request = string(buf[0:n])
	logChan <- entry
	enc, err := json.Marshal(cl)
	if err != nil {
		return err
	}
	length := len(enc)
	c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	c.Write([]byte("Connection: close\r\n"))
	c.Write([]byte("Content-Type: application/json\r\n"))
	contentLength := fmt.Sprintf("Content-Length: %d\r\n", length)
	c.Write([]byte(contentLength))
	c.Write([]byte("\r\n"))
	c.Write(enc)
	return nil
}

func main() {
	if err := flags.Validate(); err != nil {
		zlog.Fatal(err.Error())
	}
	certificate, certErr := ztls.LoadX509KeyPair(flags.CertificateChainPath, flags.KeyPath)
	if certErr != nil {
		zlog.Fatal(certErr.Error())
	}

	var tlsConfig ztls.Config
	tlsConfig.SessionTicketsDisabled = true
	tlsConfig.Certificates = []ztls.Certificate{certificate}
	listener, err := ztls.Listen("tcp", flags.ListenAddress, &tlsConfig)
	if err != nil {
		zlog.Fatal(err.Error())
	}

	// Open errors file
	errorFile, oErr := os.OpenFile(flags.ErrorFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if oErr != nil {
		zlog.Fatal(oErr.Error())
	}
	errorLog := zlog.New(errorFile, "cipher-suite-echo")

	// Open log file
	logFile := os.Stderr
	if flags.LogFileName != "-" {
		f, err := os.OpenFile(flags.LogFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			zlog.Fatal(err.Error())
		}
		logFile = f
	}

	logChan = make(chan HostLogEntry, 1024)

	go func() {
		encoder := json.NewEncoder(logFile)
		for {
			entry := <-logChan
			encoder.Encode(entry)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			errorLog.Error(err.Error())
			continue
		}
		c := conn.(*ztls.Conn)
		go ciphers(c)
	}
}
