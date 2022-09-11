# Netgear Telnet Enabler

This utility unlocks telnet on certain Netgear routers.
Netgear routers compatable with this utility have a telnet enable daemon,
`pu_telnetEnabled` listening for unlock packets on UDP port 23.

The unlock packet consists of the router's `br0` MAC address, a username (usually 'admin'),
and a SHA256 sum of the router's administrator password.
These data fields are NULL padded and hashed with MD5.
The MD5 hash is prepended to the plaintext data.

The payload is then encrypted with blowfish.
The key is: `"AMBIT_TELNET_ENABLE+"` + a SHA256 string representation of the password hash.
The astute reader will recognize that 64 bytes of stringified password hash plus
`strlen("AMBIT_TELNET_ENABLE+")` exceeds the maximum specified key length of a blowfish key, 56.
This project makes use of the blowfish implementation found in Netgear GPL sources that
does not validate key length.

The encrypted payload is then sent to the router.
This spawns a `consoled` shell and pokes holes in the firewall with iptables.
Only the IP address who sent the packet may access the `consoled` shell.

## usage

**usage**
```
telnetenable <host ip> <host mac> <user name> <password>
```

**example**
```
telnetenable 192.168.1.1 ABCDEF123456 admin password
```

I've found that the router web interface displays the wrong MAC address.
Try using `arp` to get a proper MAC addressif the unlock isn't working.


## consoled

`consoled` will prompt you with a login.
The credentials are the same as the administrator account on your router.
`consoled` will present you with some limited options.
I've found that this is the same console you get dropped to if you connect to the router with UART.

```
?
help
logout
exit
quit
reboot
brctl
cat
virtualserver
ddns
df
loglevel
logdest
tracelocks
dumplocks
dumpoid
dumpcfg
dumpmdm
dumpeid
mdm
meminfo
kill
dumpsysinfo
exitOnIdle
syslog
echo
ifconfig
ping
ps
pwd
sntp
sysinfo
tftp
wlctl
arp
defaultgateway
dhcpserver
dns
lan
lanhosts
passwd
ppp
restoredefault
route
save
swversion
uptime
wan
mcpctl
intfgroup
```

It is not too difficult to drill through `consoled` and get a busybox shell.

