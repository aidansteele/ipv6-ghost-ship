package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/pflag"
	"os"
	"time"
)

func main() {
	var debug bool
	var secret string
	pflag.BoolVar(&debug, "debug", false, "verbose debug logging")
	pflag.StringVar(&secret, "secret", "", "totp secret")
	pflag.Parse()

	if _, err := totp.GenerateCode(secret, time.Now()); secret == "" || err != nil {
		fmt.Fprintln(os.Stderr, "--secret is mandatory and must be a 32 character string")
		os.Exit(1)
	}

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	defer nfq.Close()
	packets := nfq.GetPackets()

	if debug {
		go printCodes(context.Background(), secret)
	}

	for {
		select {
		case p := <-packets:
			p6, ok := p.Packet.NetworkLayer().(*layers.IPv6)
			if !ok {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			b0, b1, b2 := p6.DstIP[11], p6.DstIP[13], p6.DstIP[15]
			receivedCode := fmt.Sprintf("%02x%02x%02x", b0, b1, b2)
			valid := totp.Validate(receivedCode, secret)

			if debug {
				j, _ := json.Marshal(map[string]interface{}{
					"ReceivedCode": receivedCode,
					"Valid":        valid,
					"SrcIp":        p6.SrcIP.String(),
					"Packet":       fmt.Sprintf("%+v", p.Packet),
				})
				fmt.Println(string(j))
			}

			if valid {
				p.SetVerdict(netfilter.NF_ACCEPT)
			} else {
				p.SetVerdict(netfilter.NF_DROP)
			}
		}
	}
}

func printCodes(ctx context.Context, secret string) {
	now := time.Now()
	period := 30 * time.Second
	t := now.Truncate(period)

	tick := time.NewTicker(t.Add(period).Sub(now))
	first := true

	calculatedCode, _ := totp.GenerateCode(secret, now)
	fmt.Println("now expecting " + calculatedCode)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if first {
				tick = time.NewTicker(period)
				first = false
			}

			calculatedCode, _ = totp.GenerateCode(secret, time.Now())
			fmt.Println("now expecting " + calculatedCode)
		}
	}
}
