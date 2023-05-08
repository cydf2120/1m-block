#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <iostream>
#include <unordered_set>
#include <fstream>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct libnet_ipv4_hdr
{
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

std::unordered_set<std::string> blacklist;

static void usage()
{
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

/* returns packet id */
static int print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;
    struct libnet_ipv4_hdr *ipv4_hdr;
    struct libnet_tcp_hdr *tcp_hdr;
    char *http_data;
    char *host;
    int http_data_len;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    fputc('\n', stdout);

    ipv4_hdr = reinterpret_cast<struct libnet_ipv4_hdr *>(data);
    if (ipv4_hdr->ip_hl * 4 > ret)
        return id;

    tcp_hdr = reinterpret_cast<struct libnet_tcp_hdr *>((char *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
    if (ipv4_hdr->ip_hl * 4 + tcp_hdr->th_off * 4 > ret)
        return id;

    http_data = (char *)tcp_hdr + tcp_hdr->th_off * 4;
    http_data_len = ret - ipv4_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
    host = strstr(http_data, "Host: ");
    if (host == NULL)
        return id;

    host = host + sizeof("Host: ") - 1;
    for (int i = 0;;i++)
    {
        if (host[i] == '\r') 
        {
            host[i] = 0;
            break;
        }
    }
        
    if (blacklist.find(std::string(host)) == blacklist.end())
        return id;

    return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    int res;

    ph = nfq_get_msg_packet_hdr(nfa);

    id = ntohl(ph->packet_id);

    res = print_pkt(nfa);
    printf("entering callback\n");

    if (res)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        usage();
        return 0;
    }

    std::ifstream f;
    std::string host;

    f.open(argv[1], std::fstream::in);
    if (f.fail()) 
    {
        std::cerr << "Can't open file" << std::endl;
        return 1;
    }

    while (!f.eof()) 
    {
        std::getline(f, host);
        host.erase(0, host.find(',') + 1);
        blacklist.insert(host);
    }

    f.close();

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
