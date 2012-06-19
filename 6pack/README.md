6pack was a tool I made a couple of years ago. Besides being useful to learn
more about libnet and IPv6, at the time I couldn't find any fast IPv6 scanner,
so I wrote my own. It is a half open ("stealth") port scanner, using only SYN packets for the scanning process.

While writing it, I found a small bug in Libnet's IPv6 implementation, and
submited the patch to Mike Schiffman. The patch is since part of the official
Libnet distribution.

Read the libnet_ipv6_patch.txt file for more info on IPv6 support on Libnet
and on the kernel.

-- Bruno Morisson <morisson@genhex.org>
