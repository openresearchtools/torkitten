module torkitten

go 1.27.0

require (
	filippo.io/age v1.3.2
	github.com/boombuler/barcode v1.1.0
	github.com/jpillora/chisel v1.12.0
	github.com/makiuchi-d/gozxing v0.1.1
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/andrew-d/go-termutil v0.0.0-20150726205930-009166a695a2 // indirect
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jpillora/ansi v1.0.3 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jpillora/requestlog v1.0.0 // indirect
	github.com/jpillora/sizestr v1.0.0 // indirect
	github.com/tomasen/realip v0.0.0-20180522021738-f0c99a92ddce // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace github.com/jpillora/chisel => ./third-party/chisel

replace filippo.io/age => ./third-party/age

replace github.com/makiuchi-d/gozxing => ./third-party/gozxing
