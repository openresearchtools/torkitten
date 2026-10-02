module torkitten-mobile-build

go 1.27.0

require (
 golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e
 torkitten v0.0.0
)

replace torkitten => ../..
replace github.com/jpillora/chisel => ../../third-party/chisel
replace filippo.io/age => ../../third-party/age
replace github.com/makiuchi-d/gozxing => ../../third-party/gozxing
