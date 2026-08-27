// Command fpproxy is a small MITM proxy that lets Burp Suite (or any HTTP
// client) reach Cloudflare-protected targets that block non-browser clients by
// their TLS fingerprint (JA3/JA4).
//
// The problem it solves
// ---------------------
// Cloudflare (and similar WAFs) fingerprint the raw TLS ClientHello. Burp's Go/
// Java TLS stack produces a fingerprint that does not match any real browser, so
// Cloudflare serves a block / managed-challenge page and the target is
// unreachable through Burp — even though it loads fine in a normal browser.
//
// How it works
// ------------
// fpproxy is chained *downstream* of Burp:
//
//	browser -> Burp (127.0.0.1:8080) -> fpproxy (127.0.0.1:8899) -> target
//
//  1. Burp forwards traffic to fpproxy as an upstream proxy. For HTTPS, Burp
//     sends a CONNECT; fpproxy answers "200 Connection established" and then
//     terminates the TLS itself, presenting a leaf certificate it mints on the
//     fly for the requested host (signed by a local CA generated on first run —
//     see loadOrMakeCA/leafFor). Burp trusts it because Burp does not validate
//     upstream-proxy certificates.
//  2. fpproxy reads the plaintext HTTP request and re-originates it to the real
//     target over a *fresh* connection using uTLS with the HelloChrome_Auto
//     ClientHello (see forward()). To Cloudflare this looks like a genuine
//     Chrome TLS handshake, so the fingerprint check passes.
//  3. It also negotiates HTTP/2 via ALPN when the server offers it, and forces a
//     matching Chrome User-Agent, so the TLS fingerprint and the UA/protocol are
//     consistent (a mismatch would itself be a tell).
//  4. The upstream response is relayed back to Burp verbatim, so all traffic
//     still appears in Burp's HTTP history / Repeater / Intruder as normal.
//
// Note: this only fixes *fingerprint*-based blocking. Rate-based rules,
// challenges tied to real browser JS execution, etc. are unaffected — keep
// testing low-and-slow.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

var (
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leafMu  sync.Mutex
	leaves  = map[string]*tls.Certificate{}
	hopHdrs = map[string]bool{"proxy-connection": true, "connection": true, "keep-alive": true, "transfer-encoding": true, "te": true, "trailer": true, "upgrade": true}
)

func main() {
	dir := os.Getenv("FP_DIR")
	if dir == "" {
		dir = "/home/hyder/fpproxy"
	}
	os.MkdirAll(dir, 0755)
	if err := loadOrMakeCA(dir); err != nil {
		log.Fatal("CA: ", err)
	}
	addr := "127.0.0.1:8899"
	if v := os.Getenv("FP_ADDR"); v != "" {
		addr = v
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fpproxy listening on %s  (CA: %s)", addr, filepath.Join(dir, "fp-ca.der"))
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == "CONNECT" {
		// HTTPS path: Burp asks to tunnel to host:443. We accept, then MITM the
		// TLS ourselves with a leaf cert minted for this host so we can read the
		// plaintext request and re-send it with a browser fingerprint.
		host := req.URL.Hostname()
		log.Printf("CONNECT %s from %s", req.URL.Host, c.RemoteAddr())
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		cert, err := leafFor(host)
		if err != nil {
			log.Printf("  leafFor(%s) err: %v", host, err)
			return
		}
		tconn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}})
		if err := tconn.Handshake(); err != nil {
			log.Printf("  client TLS handshake FAILED for %s: %v  <-- (Burp rejected fpproxy cert; import fp-ca.der into Burp)", host, err)
			return
		}
		serveH1(tconn, host)
		return
	}
	log.Printf("plain %s %s from %s", req.Method, req.Host, c.RemoteAddr())
	// plain HTTP (rare here) — forward absolute URL
	forward(c, req, req.URL.Scheme+"://"+req.Host)
}

func serveH1(tconn *tls.Conn, host string) {
	defer tconn.Close()
	br := bufio.NewReader(tconn)
	for {
		tconn.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		forward(tconn, req, "https://"+host)
	}
}

// forward re-originates the request to the target using a Chrome uTLS handshake.
func forward(w io.Writer, req *http.Request, base string) {
	host := req.URL.Hostname()
	if host == "" {
		host = strings.Split(req.Host, ":")[0]
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	tcp, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	// The core of the bypass: perform the upstream TLS handshake with uTLS using
	// a real Chrome ClientHello (HelloChrome_Auto), so Cloudflare sees a genuine
	// Chrome JA3/JA4 fingerprint instead of Burp's Go/Java one.
	u := utls.UClient(tcp, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if err := u.Handshake(); err != nil {
		writeErr(w, err)
		tcp.Close()
		return
	}
	alpn := u.ConnectionState().NegotiatedProtocol
	log.Printf("  -> upstream %s %s (alpn=%s)", req.Method, host+req.URL.RequestURI(), alpn)

	// Build outbound request.
	url := base + req.URL.RequestURI()
	var body io.Reader
	if req.Body != nil {
		body = req.Body
	}
	out, _ := http.NewRequest(req.Method, url, body)
	for k, vv := range req.Header {
		if hopHdrs[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			out.Header.Add(k, v)
		}
	}
	out.Header.Set("User-Agent", chromeUA) // force UA to match the Chrome fingerprint

	// Speak whatever the server negotiated via ALPN: HTTP/2 if offered (matches
	// what Chrome would do), otherwise fall back to HTTP/1.1 over the uTLS conn.
	var resp *http.Response
	if alpn == "h2" {
		tr := &http2.Transport{}
		cc, err := tr.NewClientConn(u)
		if err != nil {
			writeErr(w, err)
			u.Close()
			return
		}
		resp, err = cc.RoundTrip(out)
		if err != nil {
			writeErr(w, err)
			u.Close()
			return
		}
	} else {
		if err := out.Write(u); err != nil {
			writeErr(w, err)
			u.Close()
			return
		}
		resp, err = http.ReadResponse(bufio.NewReader(u), out)
		if err != nil {
			writeErr(w, err)
			u.Close()
			return
		}
	}
	log.Printf("  <- %s %d", host, resp.StatusCode)
	// Relay response back to client as HTTP/1.1
	defer resp.Body.Close()
	defer u.Close()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)))
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if hopHdrs[lk] || lk == "content-length" {
			continue
		}
		for _, v := range vv {
			sb.WriteString(k + ": " + v + "\r\n")
		}
	}
	rb, _ := io.ReadAll(resp.Body)
	sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(rb)))
	sb.WriteString("Connection: keep-alive\r\n\r\n")
	w.Write([]byte(sb.String()))
	w.Write(rb)
}

func writeErr(w io.Writer, err error) {
	msg := "fpproxy error: " + err.Error()
	io.WriteString(w, fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(msg), msg))
}

// leafFor returns a TLS certificate for host, signed by the local CA and cached
// per host. This is what Burp sees when it connects through fpproxy; Burp trusts
// it because it does not validate upstream-proxy certs (import fp-ca.der if it
// ever does).
func leafFor(host string) (*tls.Certificate, error) {
	leafMu.Lock()
	defer leafMu.Unlock()
	if c, ok := leaves[host]; ok {
		return c, nil
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: priv}
	leaves[host] = cert
	return cert, nil
}

// loadOrMakeCA loads the local signing CA from dir, or generates one on first
// run and writes it out as fp-ca.pem/.key/.der. The .der is the file to import
// into a client's trust store (e.g. Burp) if it ever rejects fpproxy's certs.
func loadOrMakeCA(dir string) error {
	cp := filepath.Join(dir, "fp-ca.pem")
	kp := filepath.Join(dir, "fp-ca.key")
	if b, err := os.ReadFile(cp); err == nil {
		blk, _ := pem.Decode(b)
		caCert, _ = x509.ParseCertificate(blk.Bytes)
		kb, _ := os.ReadFile(kp)
		kblk, _ := pem.Decode(kb)
		caKey, _ = x509.ParseECPrivateKey(kblk.Bytes)
		if caCert != nil && caKey != nil {
			return nil
		}
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fpproxy CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	caCert, _ = x509.ParseCertificate(der)
	caKey = priv
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	kb, _ := x509.MarshalECPrivateKey(priv)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	os.WriteFile(filepath.Join(dir, "fp-ca.der"), der, 0644)
	return nil
}
