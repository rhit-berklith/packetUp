#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    printf("Captured packet of length: %d\n", header->len);
    // Print first few bytes of the packet
    for (int i = 0; i < header->len && i < 32; ++i) {
        printf("%02x ", pkt_data[i]);
    }
    printf("\n");
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // List all devices
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found.\n");
        return 1;
    }

    int dev_num;
    printf("Enter the interface number to use: ");
    scanf("%d", &dev_num);

    // Get selected device
    for (d = alldevs, i = 1; i < dev_num; d = d->next, i++);

    // Open device
    pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open adapter: %s\n", errbuf);
        return 1;
    }

    printf("Listening on %s...\n", d->name);

    // Start capture loop
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
