![night chan](./night%20chan.png)

it has the zoomies

so quick story abt how this was made, this was the initial project, then amplify made me write a whole new wisp library, then i scrapped that and wrote this in rust. this has still been faster than all of them. every single time.

## Features

- Wisp v1 and v2 protocol support
- TCP and UDP stream multiplexing over WebSocket
- Twisp (terminal over wisp) support for remote shell access
- Password and Ed25519 certificate authentication (v2)
- Hostname blacklist/whitelist filtering
- SOCKS5 proxy support for upstream connections
- Custom DNS server with caching
- WebSocket permessage-deflate compression
- Configurable TCP buffer sizes and flow control

## Installation

```bash
go build -o mrrowisp
```

## Configuration

Copy `example.config.json` to `config.json` and edit as needed:

```json
{
	"port": "6001",
	"disableUDP": false,
	"tcpBufferSize": 65535,
	"bufferRemainingLength": 1024,
	"tcpNoDelay": true,
	"websocketTcpNoDelay": true,
	"blacklist": {
		"hostnames": []
	},
	"whitelist": {
		"hostnames": []
	},
	"proxy": "",
	"websocketPermessageDeflate": false,
	"dnsServer": "",
	"enableTwisp": false,
	"enableV2": true,
	"motd": "",
	"passwordAuth": false,
	"passwordAuthRequired": false,
	"passwordUsers": {},
	"certAuth": false,
	"certAuthRequired": false,
	"certAuthPublicKeys": [],
	"enableStreamConfirm": false
}
```

### Configuration Options

| Option                       | Type     | Description                                   |
| ---------------------------- | -------- | --------------------------------------------- |
| `port`                       | string   | Port to listen on                             |
| `disableUDP`                 | bool     | Disable UDP stream support                    |
| `tcpBufferSize`              | int      | TCP read buffer size                          |
| `bufferRemainingLength`      | uint32   | Flow control buffer threshold                 |
| `tcpNoDelay`                 | bool     | Enable TCP_NODELAY on outbound connections    |
| `websocketTcpNoDelay`        | bool     | Enable TCP_NODELAY on WebSocket connections   |
| `blacklist.hostnames`        | []string | Hostnames to block                            |
| `whitelist.hostnames`        | []string | Hostnames to bypass DNS resolution            |
| `proxy`                      | string   | SOCKS5 proxy address (e.g., `127.0.0.1:1080`) |
| `websocketPermessageDeflate` | bool     | Enable WebSocket compression                  |
| `dnsServer`                  | string   | Custom DNS server (e.g., `8.8.8.8:53`)        |
| `enableTwisp`                | bool     | Enable terminal streams (Unix only)           |
| `enableV2`                   | bool     | Enable Wisp v2 protocol                       |
| `motd`                       | string   | Message of the day sent to v2 clients         |
| `passwordAuth`               | bool     | Enable password authentication                |
| `passwordAuthRequired`       | bool     | Require password authentication               |
| `passwordUsers`              | object   | Username/password map                         |
| `certAuth`                   | bool     | Enable Ed25519 certificate authentication     |
| `certAuthRequired`           | bool     | Require certificate authentication            |
| `certAuthPublicKeys`         | []string | Allowed Ed25519 public keys (hex-encoded)     |
| `enableStreamConfirm`        | bool     | Send confirmation when streams connect        |

## Usage

```bash
./mrrowisp
```

The server will start listening on the configured port. Connect with any Wisp-compatible client.

## Credits
 - [soap phia](https://github.com/soap-phia/) - writing most of this
 - [rebecca](https://github.com/rebeccaheartz69/) - greatly helping with implementing wisp v2 and extensions
 - [ObjectAscended](https://github.com/ObjectAscended/) - writing [go-wisp](https://github.com/ObjectAscended/go-wisp/), which this was initially based off of