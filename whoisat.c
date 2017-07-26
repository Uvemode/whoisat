#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <pthread.h>

pcap_t* cap_handler;

int send_packet(char *mac, char *interface)
{

    struct in_addr self, network, netmask, broadcast, hosts;
    char err_buff[PCAP_ERRBUF_SIZE];

    struct ifaddrs *ifap, *iter;
    getifaddrs(&ifap);

    int interface_found = 0;
    for(iter = ifap; iter; iter = iter->ifa_next)
    {
        if (iter->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *if_addr;
            
            if (!strcmp(iter->ifa_name, interface))
            {
                interface_found = 1;

                if_addr = (struct sockaddr_in *)iter->ifa_addr;
                self.s_addr = if_addr->sin_addr.s_addr;

                char ip_str[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &if_addr->sin_addr,ip_str,INET_ADDRSTRLEN))
                {
                    perror("Error converting IP to string: ");
                    return 1;
                }

                bpf_u_int32 ip_holder, netmask_holder;
                if (pcap_lookupnet(interface, &ip_holder, &netmask_holder, err_buff) < 0)
                {
                    perror("Error obtaining interface information: ");
                    return 1;
                }

                network.s_addr = ip_holder;
                netmask.s_addr = netmask_holder;
                broadcast.s_addr = ip_holder | (~netmask_holder);
            }
        }
    }

    if (!interface_found)
    {
        printf("%s interface not found\n", interface);
        return 1;
    }

    struct ifreq ifr;

    size_t if_name_len = strlen(interface);
    if(if_name_len < sizeof(ifr.ifr_name)) 
    {
        memcpy(ifr.ifr_name, interface, if_name_len);
        ifr.ifr_name[if_name_len] = '\0';
    }

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        perror("Error at creating socket: ");
        return 1;
    }    

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
    {
        perror("Error at obtaining interface hwaddr: ");
        return 1;
    }

    if (close(sock) < 0)
    {
        perror("Error at closing socket: ");
        return 1;
    }

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
        perror("Interface is not ethernet: ");
    }

    struct ether_header eth_header;
        eth_header.ether_type = htons(ETHERTYPE_ARP);
        memset(eth_header.ether_dhost, 0xff, sizeof(eth_header.ether_dhost));
        const unsigned char *hwaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        strncpy(eth_header.ether_shost, hwaddr, sizeof(eth_header.ether_shost));

    struct ether_arp arp_header;
        arp_header.arp_hrd = htons(ARPHRD_ETHER);
        arp_header.arp_pro = htons(ETH_P_IP);
        arp_header.arp_hln = ETHER_ADDR_LEN;
        arp_header.arp_pln = sizeof(in_addr_t);
        arp_header.arp_op = htons(ARPOP_REQUEST);
        memcpy(&arp_header.arp_spa, &self.s_addr, sizeof(arp_header.arp_spa));
        memcpy(arp_header.arp_sha, hwaddr, sizeof(arp_header.arp_sha));

    pcap_t *open_pcap = pcap_open_live(interface, BUFSIZ, 1, 100, err_buff);
    if (!open_pcap)
    {
        printf("Error opening interface for sending: %s\n", err_buff);
        return 1;
    }

    uint32_t first_host, last_host;
    first_host = ntohl(network.s_addr);
    last_host = ntohl(broadcast.s_addr);

    for(uint32_t i = first_host + 1; i <= last_host; i++)
    {
        hosts.s_addr = htonl(i);
        memcpy(arp_header.arp_tpa, &hosts, sizeof(uint32_t));
        u_char full_header[sizeof(struct ether_header)+sizeof(struct ether_arp)];
        memcpy(full_header,&eth_header, sizeof(struct ether_header));
        memcpy(full_header+sizeof(struct ether_header),&arp_header, sizeof(struct ether_arp));
        pcap_inject(open_pcap, full_header,sizeof(full_header));
    }

    pcap_close(open_pcap);
    return 0;
}

void get_packet(u_char *mac, const struct pcap_pkthdr *header, const u_char *packet)
{   
    const struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;

    char ip[18];
    char source_mac[18];
    sprintf(source_mac, "%02X:%02X:%02X:%02X:%02X:%02X",eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    if (!strcmp(source_mac, mac))
    {
        if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
        {
            const struct ether_arp* arp_header;
            arp_header = (struct ether_arp*)(packet + 14);
            sprintf(ip, "%d.%d.%d.%d", arp_header->arp_spa[0], arp_header->arp_spa[1], arp_header->arp_spa[2], arp_header->arp_spa[3]);
            printf("%s is at %s\n",mac, ip);
            pcap_breakloop(cap_handler);    
        }
        else if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
        {
            const struct ip *ip_header;
            ip_header = (struct ip*)(packet + sizeof(struct ether_header));

            inet_ntop(AF_INET, &ip_header->ip_src, ip, INET_ADDRSTRLEN);
            printf("%s is at %s\n",mac, ip);
            pcap_breakloop(cap_handler);
        }
    }
}

int begin_capturing(char *mac, char *interface)
{
    char err_buff[PCAP_ERRBUF_SIZE];

    cap_handler = pcap_open_live(interface, BUFSIZ, 0, 100, err_buff);
    if (!cap_handler)
    {
         printf("Error creating handler: %s\n",err_buff);
         exit(1);
    }
    if (pcap_loop(cap_handler, 0, get_packet, mac) == -1)
    {
        printf("Error at loop begin: %s\n", err_buff);
        exit(1);
    }

    return 0;
}

void *cap_thread(void *args)
{
    char **string_args = args;
    if (begin_capturing(string_args[0], string_args[1]))
    {
        printf("Error at begin_capturing()\n");
    }
}

int check_interface(char *interface)
{
    char err_buff[PCAP_ERRBUF_SIZE];
    pcap_if_t* device_list;
    pcap_if_t* device;

    if (pcap_findalldevs(&device_list, err_buff) == -1)
    {
        printf("Error listing devices, error code: %s\n",err_buff);
        //error_dialog(err_buff);
        exit(1);
    }

    while (strcmp(device_list->name,interface) != 0)
    {
        if (device_list->next == NULL)
        {
            return 1;
        }
        device_list = device_list->next;
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    if (getuid())
    {
        printf("whoisat must be run as root\n");
        exit(1);
    }
    if (argc != 3)
    {
        printf("Usage: whoisat [MAC] [interface]\n");
        exit(1);
    }
    else if ( (strlen(argv[1]) != 17) || argv[1][2] != ':' || argv[1][5] != ':' || argv[1][8] != ':' || argv[1][11] != ':' || argv[1][14] != ':' )
    {
        printf("\"%s\" is not a valid MAC address.\nMust be XX:XX:XX:XX:XX:XX.\n",argv[1]);
        exit(1);
    }

    pthread_t cap_function;
    char *thread_args[2];
    thread_args[0] = strdup(argv[1]);
    thread_args[1] = strdup(argv[2]);

    if (check_interface(thread_args[1]))
    {
        printf("\"%s\" interface not found\n", thread_args[1]);
        exit(1);
    }

    for (int i = 0; i < strlen(thread_args[0]); i++)
    {
        if (!isupper(thread_args[0][i]))
        {
            thread_args[0][i] = toupper(thread_args[0][i]);
        }
    }
   
    if (pthread_create(&cap_function, NULL, cap_thread, (void*)thread_args))
    {
        perror("Error at thread creation: ");
        exit(1);
    }

    sleep(1);

    if (send_packet(thread_args[0], thread_args[1]))
    {
        printf("Error at send_packet()\n");
        return 0;
    }

    if (pthread_join(cap_function, NULL))
    {
        perror("Error waiting for thread: ");
    }
    return 0;
}
