# whoisat

whoisat is a small tool that given a MAC address returns the IP address assign to it, as long as the host is in the same network/subnet as you, by sending an ARP packet to the whole network and parsing the MAC source with the selected one.
Usage: whoisat [MAC] [interface]

The MAC address must be all capitalized.

  Disclaimer:
  whoisat doesn't perform any kind of check on the interface, like datalink, or if the device can be put in promiscous mode.
