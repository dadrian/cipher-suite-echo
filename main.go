package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/zmap/zgrab/ztools/zlog"
	"github.com/zmap/zgrab/ztools/ztls"
)

type Flags struct {
	CertificateChainPath string
	KeyPath              string
	LogFileName          string
	ListenAddress        string
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

var logger *zlog.Logger

func init() {
	flag.StringVar(&flags.CertificateChainPath, "certificate", "", "Path to certificate chain (PEM encoded)")
	flag.StringVar(&flags.KeyPath, "key", "", "Path to key corresponding to certificate (PEM encoded, decrypted)")
	flag.StringVar(&flags.ListenAddress, "listen-address", "127.0.0.1:443", "ip:port to listen on")
	flag.StringVar(&flags.LogFileName, "log-file", "-", "defaults to stderr")
	flag.Parse()
}

type CipherList struct {
	Ciphers []ztls.CipherSuite `json:"ciphers"`
}

type HostLogEntry struct {
	Host    string             `json:"ip_address"`
	Ciphers []ztls.CipherSuite `json:"ciphers"`
}

func ciphers(c *ztls.Conn) error {
	if err := c.Handshake(); err != nil {
		logger.Info(err.Error())
		return err
	}
	defer c.Close()
	cl := CipherList{}
	hl := HostLogEntry{}
	cl.Ciphers = c.ClientCiphers()
	hl.Ciphers = cl.Ciphers
	buf := make([]byte, 1024)
	c.Read(buf)
	enc, err := json.Marshal(cl)
	if err != nil {
		logger.Info(err.Error())
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
	tlsConfig.Certificates = []ztls.Certificate{certificate}
	listener, err := ztls.Listen("tcp", flags.ListenAddress, &tlsConfig)
	if err != nil {
		zlog.Fatal(err.Error())
	}

	// Open log file
	if flags.LogFileName == "-" {
		logger = zlog.New(os.Stderr, "cipher-echo")
	} else {
		logFile, err := os.Create(flags.LogFileName)
		if err != nil {
			zlog.Fatal(err)
		}
		logger = zlog.New(logFile, "cipher-echo")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			zlog.Info(err.Error())
			continue
		}
		c := conn.(*ztls.Conn)
		go ciphers(c)
	}
	return
}
