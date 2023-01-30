/**
 * @file ipk-sniffer.c
 * @author Ivan Golikov (xgolik00)
 * @date 2022-04-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include <sys/time.h>
#include <time.h>
#include <ctype.h>

#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/ether.h>

pcap_t* handle;
int linkhdrlen;
int countPacket;


// function for writing help
void printHelp() {

    printf("usage: ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
    printf("\t-h | --help                 help message\n");
    printf("\t-i                          specify interface\n");
    printf("\t-p                          set packet port to filter\n");
    printf("\t-t | --tcp                  filter TCP packets\n");
    printf("\t-u | --udp                  filter UDP packets\n");
    printf("\t--arp                       filter ARP frames\n");
    printf("\t--icmp                      filter ICMPv4 nad ICMPv6 packets\n");
    printf("\t-n                          set packet limit (unlimited if not set)\n");
}

// function to write a list of all available interfaces
void printInterfaces() {

    pcap_if_t *alldevs;
    pcap_if_t *i;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    int index = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    printf("List of interfaces:\n");
    for (i = alldevs; i != NULL; i = i->next) {
        printf("%d:\t\t%s\n", ++index, i->name);
    }

    pcap_freealldevs(alldevs);
}

// function for writing out statistics and stopping the packet capture handle
void stopCapture() {

    struct pcap_stat stats;
 
    if (pcap_stats(handle, &stats) >= 0) {
        printf("\n%d packets captured\n", countPacket);
        printf("%d packets received by filter\n", stats.ps_recv); 
        printf("%d packets dropped\n\n", stats.ps_drop);
    }

    pcap_close(handle);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Create a Pcap Handle object
 * 
 * @param device - used interface 
 * @param filter - sort filter
 * @return pcap_t* - generated packet capture handle
 */
pcap_t* createPcapHandle(char* device, char* filter) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    uint32_t netmask;
    uint32_t srcip;

    // open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        return NULL;
    }

    // convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 1, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // bind the packet filter to the libpcap handle.    
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

/**
 * @brief Get the Link Header Length object
 * 
 * @param handle - packet capture handle
 */
void getLinkHeaderLen(pcap_t* handle) {

    int linktype;
 
    // determine the datalink layer type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    case DLT_LINUX_SLL:
        linkhdrlen = 16;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        linkhdrlen = 0;
    }
}

// count and write time
void printTime () {

    //get time (Year, Month, Date, Hours, Minutes, Seconds)
    char timeBuf[32];
    time_t mTime = time(NULL);
    struct tm * tm_info = localtime(&mTime);
    strftime(timeBuf, 32, "%Y-%M-%dT%X", tm_info);

    //get time (Miliseconds)
    struct timeval time;
    gettimeofday(&time, NULL);

    printf("timestamp: %s.%03ld+01:00\n", timeBuf, (long int) time.tv_usec);
}

// write info about packet
void printInfo (char* srcIp, char* dstIp, int frameLen, int sport, int dport, struct ether_header* eptr) {
    printTime();
    printf("src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
    printf("dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
    printf("frame length: %d bytes\n", frameLen);
    printf("src IP: %s\n", srcIp);
    printf("dst IP: %s\n", dstIp);
    printf("src port: %d\n", sport);
    printf("dst port: %d\n\n", dport);
}

// write packet data
void printData(unsigned char *packet, int size, int headSize) {

    bool headPrinted = false;
    int i = 0, j = 0;

    int line_counter = 1; 

    int afterHeaderOffset = headSize % 16;

    printf("0x0000:");

    // for cycle every element of the packet (packet size)
    for (i = 0; i < size; i++) {

        // if it finished the hexa line or head is printing
        if (headPrinted ? ((i - afterHeaderOffset) % 16 == 0 && i != headSize) : (i != 0 && i % 16 == 0)) {

            printf(" ");
            for (j = i - 16; j < i; j++) {
                if (isprint(packet[j])) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }

                if (j == i - 9) {
                    printf(" ");
                }
            }
            printf("\n");

            if (line_counter < 10) printf("0x00%d:", line_counter++ * 10);
            else if (line_counter < 100) printf("0x0%d:", line_counter++ * 10);
            else printf("0x%d:", line_counter++ * 10);
        }
        
        // two spaces after the 0x0000 etc.
        if ((headPrinted ? i - afterHeaderOffset : i) % 16 == 0) {
            printf("  ");
        }
        
        // space between each 8 bytes in hexa
        if ((((headPrinted ? i - afterHeaderOffset : i) - 8) % 16) == 0) {
            printf(" ");
        }

        // this prints the hexa representation
        printf("%02X ", (unsigned char) packet[i]);

        // process the last line of head or last line of packet
        if ((i == size - 1) || (headSize - 1 == i)) {
            
            // print the missing spaces to fill the line
            for (j = 0; j < 15 - ((headPrinted ? i - afterHeaderOffset : i) % 16); j++) {

                printf("   ");
                if (j == 7) printf(" ");
            }

            if (headSize != size) 
                headPrinted = !headPrinted;

            printf(" ");

            // now print the rest of the data
            for (j = (!headPrinted ? (headSize == size) ? (i - (i % 16)) : (i - ((i - afterHeaderOffset) % 16)) : headSize - afterHeaderOffset);

                j <= (!headPrinted ? i : headSize - 1); j++) {
                if (isprint(packet[j])) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }

                if (headPrinted) {
                    if (j == headSize - (headSize % 16) + 7) printf(" ");
                }
                else {
                    if (headSize == size) {
                        if (j == i - (i % 16) + 7) printf (" ");
                    }
                    else {
                        if (j == i - ((i - afterHeaderOffset) % 16) + 7) printf(" ");
                    }
                }
            }

            // if ending the head, print next line counter
            if (headPrinted && headSize != size) {
                printf("\n\n");
                if (line_counter < 10) printf("0x00%d:", line_counter++ * 10);
                else if (line_counter < 100) printf("0x0%d:", line_counter++ * 10);
                else printf("0x%d:", line_counter++ * 10);
            } else {
                printf("\n");
            }
        }
    }
}

/**
 * @brief function for parsing pacekts
 * 
 * @param user - description
 * @param packethdr - structure containing info about packet
 * @param packetptr - pointer to the first char of packet
 */
void packetHandler(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr) {

    bool isIPV4 = false;

    char srcIp[256];
    char dstIp[256];
    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;
    int offsetHeader = 0;
    int nextHeader = -1;

    u_char * tempPtr = packetptr + linkhdrlen;

    struct ether_header* eptr= (struct ether_header *) packetptr;

    // define ether type
    int etherType = ntohs(eptr->ether_type);

    // ether type for ipv4 
    if (etherType == 2048) {
        isIPV4 = true;
        iphdr = (struct ip *) tempPtr;

        //copy ip adresses
        inet_ntop(AF_INET, &(iphdr->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), dstIp, INET_ADDRSTRLEN);

        tempPtr += 4 * iphdr->ip_hl;
        
    // ether type for ipv6
    } else if (etherType == 34525) {
        isIPV4 = false;
        ip6hdr = (struct ip6_hdr *) tempPtr;

        //copy ip adresses
        inet_ntop(AF_INET6, &(ip6hdr->ip6_src), srcIp, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6hdr->ip6_dst), dstIp, INET6_ADDRSTRLEN);


        nextHeader = ip6hdr->ip6_nxt;
        offsetHeader += 40;
        tempPtr += 40;

        //define ipv6 type
        switch (nextHeader) {
            case IPPROTO_ROUTING:;
                struct ip6_rthdr * header =  (struct ip6_rthdr *) tempPtr;
                tempPtr += sizeof(struct ip6_rthdr);
                offsetHeader += sizeof(struct ip6_rthdr);
                nextHeader = header->ip6r_nxt;
                break;

            case IPPROTO_HOPOPTS:;
                struct ip6_hbh * header1 =  (struct ip6_hbh *) tempPtr;
                tempPtr += sizeof(struct ip6_hbh);
                offsetHeader += sizeof(struct ip6_hbh);
                nextHeader = header1->ip6h_nxt;
                break;

            case IPPROTO_FRAGMENT:;
                struct ip6_frag * header2 =  (struct ip6_frag *) tempPtr;
                tempPtr += sizeof(struct ip6_frag);
                offsetHeader += sizeof(struct ip6_frag);
                nextHeader = header2->ip6f_nxt;
                break;

            case IPPROTO_DSTOPTS:;
                struct ip6_dest * header3 =  (struct ip6_dest *) tempPtr;
                packetptr += sizeof(struct ip6_dest);
                tempPtr += sizeof(struct ip6_dest);
                nextHeader = header3->ip6d_nxt;
                break;

            default:
                break;
        }

    } else {
        return;
    }

    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    switch (isIPV4 ? iphdr->ip_p : nextHeader) {    
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *) tempPtr;
		    
            printInfo(srcIp, dstIp, packethdr->len, ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport), eptr);

            if (isIPV4) {
                printData(packetptr, packethdr->caplen, linkhdrlen + 4 * iphdr->ip_hl + 4 * tcphdr->doff);
            } else {
                printData(packetptr, packethdr->caplen, linkhdrlen + offsetHeader + 4 * tcphdr->doff);
            }

    		printf("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            break;
    
        case IPPROTO_UDP:
            udphdr = (struct udphdr *) tempPtr;

            printInfo(srcIp, dstIp, packethdr->len, ntohs(udphdr->uh_sport), ntohs(udphdr->uh_dport), eptr);

            if (isIPV4) {
                printData(packetptr, packethdr->caplen, linkhdrlen + 4 * iphdr->ip_hl + 8);
            } else {
                printData(packetptr, packethdr->caplen, linkhdrlen + offsetHeader + 8);
            }

    		printf("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            break;

        case IPPROTO_ICMP:

            printInfo(srcIp, dstIp, packethdr->len, 0, 0, eptr);

            if (isIPV4) {
                printData(packetptr, packethdr->caplen, linkhdrlen + 4 * iphdr->ip_hl + 4);
            } else {
                printData(packetptr, packethdr->caplen, linkhdrlen + offsetHeader + 4);
            }

    		printf("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            break;
    }
    
}

int main (int argc, char **argv) {

    char interface[256] = "";
    char port[16] = "port ";
    int limit = 1;
    bool handleTCP = false;
    bool handleUDP = false;
    bool handleARP = false;
    bool handleICMP = false;
    int counterOfFilter = 0;
    char expressionForPCAP[256] = "";


    // parsing params

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp", no_argument, 0, 'c'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while((opt = getopt_long(argc, argv, "n:p:i:tuh", long_options, NULL)) != -1) { 
        switch(opt) 
        { 
            case 'i': 
                strcat(interface, optarg);
                break;
            case 'p': 
                strcat(port, optarg);
                break; 
            case 'n': 
                limit = atoi(optarg);
                break; 
            case 'h': 
                printHelp();
                break;
            case 't': 
                handleTCP = true;
                counterOfFilter++;
                break; 
            case 'u': 
                handleUDP = true;
                counterOfFilter++;
                break; 
            case 'a': 
                handleARP = true;
                counterOfFilter++;
                break; 
            case 'c': 
                handleICMP = true;
                counterOfFilter++;
                break; 
        } 
    } 


    // if empty -i or --interface
    if (strcmp(interface, "") == 0) {
        printInterfaces();
        exit(EXIT_FAILURE);
    }

    // conflicting of filters
    if (counterOfFilter > 1 && counterOfFilter < 4) {
        printf("More than one filter installed\n"); 
        exit(EXIT_FAILURE);
    }

    // filters of expression for pcap
    if (handleTCP == true && counterOfFilter != 4) {
        strcat(expressionForPCAP, "tcp ");
    }

    if (handleUDP == true && counterOfFilter != 4) {
        strcat(expressionForPCAP, "udp ");
    }
        
    if (handleARP == true && counterOfFilter != 4) {
        strcat(expressionForPCAP, "arp ");
    }

    if (handleICMP == true && counterOfFilter != 4) {
        strcat(expressionForPCAP, "icmp ");
    }

    if (strcmp(port, "port ") != 0) {
        strcat(expressionForPCAP, port);
    } 

    signal(SIGINT, stopCapture);
    signal(SIGTERM, stopCapture);
    signal(SIGQUIT, stopCapture);

    // create packet capture handle.
    handle = createPcapHandle(interface, expressionForPCAP);
    if (handle == NULL) {
        exit(EXIT_FAILURE);
    }

    // get the type of link layer.
    getLinkHeaderLen(handle);
    if (linkhdrlen == 0) {
        exit(EXIT_FAILURE);
    }

    // start the packet capture with a set count or continually if the count (limit) is 0.
    if (pcap_loop(handle, limit, (pcap_handler) packetHandler, (u_char*) NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    stopCapture();
}