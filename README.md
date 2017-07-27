# whoisat

whoisat is a small tool that returns the IP address assign to a given MAC addres, by sending an ARP packet to the whole network of the selected interface and looking at the source MAC address of the responses. 

whoisat will listen **15 seconds** for the response, after that the program will terminate, informing that the host wasn't found. You can change this value at **line 299**.

Usage: whoisat [MAC] [interface]
