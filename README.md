# `ipv6-ghost-ship`

[Twitter thread 🐦](https://twitter.com/__steele/status/1478904436747427840)

As of [July 2021][aws-blog], AWS EC2 instances can be assigned IPv4 and IPv6 
address prefixes. The IPv6 prefixes are `/80`, which gives your EC2 instance
281,474,976,710,656 IP addresses to play with. You _could_ use the feature to
run 281 trillion containers with their own IPs (which I assume is what AWS 
intended for the feature), but I wanted to find a more fun use.

SSH doesn't support [TOTP][totp] (those six digit codes that change every 30
seconds) out of the box. Neither does Telnet, plain old HTTP or any number of
protocols. So I thought it would be fun to add TOTP support to **every protocol**
by embedding the six digit code _inside the IP address_.

## Usage

Generate a QR code and shared secret using the `generate/generate` command. Use
that QR code with an app like Google Authenticator and keep the shared secret for
usage later.

Start an EC2 instance in an IPv6-enabled subnet:

```
aws ec2 run-instances \
  --instance-type m6g.medium
  --min-count 1 \
  --max-count 1 \
  --key-name $KeyName
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-arm64-gp2 \
  --network-interfaces SubnetId=$SubnetId,Ipv6PrefixCount=1,DeviceIndex=0,Groups=$SecurityGroupId
```

On that instance run the following commands to enable IPv6:

```
mac=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/)
prefix=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/${mac}ipv6-prefix)
ip route add local $prefix dev eth0
ip addr add local $prefix dev eth0
```

Now you can build the ghost ship:

```
sudo yum install libnetfilter_queue-devel
go build
sudo setcap cap_net_admin=+ep ipv6-ghost-ship # this means it can run without sudo
```

Now create an `iptables` rule to only allow incoming connections to IP addresses
that are permitted by `ipv6-ghost-ship`:

```
ip6tables -A INPUT -p ip -m state --state NEW -j NFQUEUE --queue-num 0
```

Start the ghost ship:

```
./ipv6-ghost-ship --secret AZCHNJHC42T3PCHNLQPJAEBMFLEXAMPLE
```

Now from your local computer, try `ping6` or `ssh` or anything. If your EC2
instance was assigned the prefix `2406:da1c:176:a202:ee3f/80` and your
authenticator app currently says the code is 123456, then you would run:

```
ssh ec2-user@2406:da1c:176:a202:ee3f:12:34:56
                                   # ^ this is where the magic happens
```

You will connect successfully! If you try that again a minute later, no such
luck. If you had tried any other suffix on that IP address, your connections
will also be dropped.

## why though

Because [Massimo implied I wasn't clown-ish][challenge-accepted].

[aws-blog]: https://aws.amazon.com/about-aws/whats-new/2021/07/amazon-virtual-private-cloud-vpc-customers-can-assign-ip-prefixes-ec2-instances/
[totp]: https://en.wikipedia.org/wiki/Time-based_One-Time_Password
[challenge-accepted]: https://twitter.com/mreferre/status/1438530190632787969
