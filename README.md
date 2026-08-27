# fpproxy — Cloudflare fingerprint proxy for Burp

Lets Burp Suite reach Cloudflare-protected targets (e.g. target.example.com) that
block Burp's default TLS fingerprint. It sits downstream of Burp and re-originates
every request with a real Chrome TLS (uTLS) + HTTP/2 fingerprint and a matching
Chrome User-Agent, so Cloudflare sees a genuine browser.

Chain:  browser -> Burp (127.0.0.1:8080) -> fpproxy (127.0.0.1:8899) -> target

## 1. Run fpproxy
Pick the binary for the laptop's OS and run it in a terminal. Leave it running.

- Linux:        ./fpproxy-linux-amd64
- macOS (Apple): ./fpproxy-macos-apple      (first run: right-click > Open, or: xattr -d com.apple.quarantine ./fpproxy-macos-apple)
- macOS (Intel): ./fpproxy-macos-intel
- Windows:      double-click fpproxy-windows-amd64.exe  (or run it in cmd/PowerShell)

It prints:  fpproxy listening on 127.0.0.1:8899
It creates fp-ca.* files next to itself on first run — that's normal, no action needed.

## 2. Configure Burp (one time)
1. If the "Awesome TLS" extension is installed: Extensions -> select it -> Remove.
2. Settings -> Network -> Connections -> Upstream Proxy Servers -> Add:
     Enabled:          (ticked)
     Destination host: *
     Proxy host:       127.0.0.1
     Proxy port:       8899
     Auth type:        None
   Make sure this is the ONLY rule.

## 3. Use it
Burp -> Proxy -> Open Browser -> browse the target. It loads, and all traffic is
in Burp (HTTP history / Repeater / Intruder) as normal.

## Notes
- Browser choice doesn't matter — fpproxy forces a Chrome UA to match its Chrome
  fingerprint, so Burp's built-in browser or Firefox both work.
- Burp accepts fpproxy's upstream cert automatically (it doesn't validate upstream
  certs). If it ever complains, import the fp-ca.der that fpproxy created into Burp.
- To rebuild from source (needs Go 1.24+):  go build -o fpproxy .
- Keep throttled / low-and-slow on the engagement; the fingerprint fix doesn't change
  rate-based rules.
