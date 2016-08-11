About JICMP6

JICMP6 is a small library to allow the use of IPv6 ICMP (raw) packets in Java.

Using JICMP6 as non-root
========================

Mac OS X supports non-root ICMP through the SOCK\_DRGAM interface, which JICMP
uses by default.

Linux supports this as well, but you additionally need to set a sysctl OID
to allow ping for non-root users.

You can set this temporarily by running: 
 
```
sysctl -w net.ipv4.ping_group_range="0 429496729"
```

...or by creating a sysctl configuration file in /etc:

```
echo "net.ipv4.ping_group_range=0 429496729" > /etc/sysctl.d/03-non-root-icmp.conf
```
