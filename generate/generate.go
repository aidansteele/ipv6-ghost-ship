package main

import (
	"bytes"
	"fmt"
	"github.com/pquerna/otp/totp"
	"image/png"
	"io/ioutil"
)

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ipv6-ghost-ship",
		AccountName: "you",
	})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	img, err := key.Image(200, 200)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	buf := bytes.Buffer{}
	err = png.Encode(&buf, img)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	err = ioutil.WriteFile("qr.png", buf.Bytes(), 0755)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	fmt.Println("Wrote QR code to qr.png")
	fmt.Printf("Secret (for ipv6-ghost-ship --secret ... usage) is %s\n", key.Secret())
}
