#include <rohc/rohc.h>
#include "network.h"

#include <iostream>
#include <cstdlib>

#include <cstdio>

#ifdef _MSC_VER
	#define snprintf _snprintf
#endif

using namespace std;

namespace 
{
    uint32_t OneChecksum(const uint8_t* data, size_t size)
    {
        uint32_t cs = 0;
        uint16_t* ptr = (uint16_t*) data;
        size_t cnt = size;
        
        while (cnt > 1)
        {
            cs += *ptr++;
            cnt -= 2;
        }
        
        if (cnt)
        {
            cs += data[size - 1] << 8;
        }
        
        return cs;
    }
    
    uint16_t OneComplementCs(const uint8_t* data, size_t size)
    {
        uint32_t cs = OneChecksum(data, size);
        while (cs >> 16)
        {
            cs = (cs & 0xffff) + (cs >> 16);
        }
        cs = ~cs;
        
        return static_cast<uint16_t>(cs);
    }    
} // ns anon

namespace ROHC
{
    void calculateIpHeaderCheckSum(iphdr* iph)
    {
        iph->check = 0;
        iph->check = OneComplementCs(reinterpret_cast<uint8_t*>(iph), 4 * (iph->ihl));
    }
    
    void calculateUdpHeaderCheckSum(iphdr* ip)
    {
        udphdr* udp = reinterpret_cast<udphdr*>(reinterpret_cast<uint8_t*>(ip) + ip->ihl * 4);
        udp->check = 0;

        uint32_t sum = OneChecksum(reinterpret_cast<uint8_t*>(udp), rohc_htons(udp->len));
        
        uint16_t* psaddr = reinterpret_cast<uint16_t*>(&ip->saddr);
        uint16_t* pdaddr = reinterpret_cast<uint16_t*>(&ip->daddr);
        
        sum += rohc_htons(ip->protocol) + udp->len +
            psaddr[0] + psaddr[1] +
            pdaddr[0] + pdaddr[1];
        
        while (sum >> 16)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        
        sum = ~sum;
        
        uint16_t csum = static_cast<uint16_t>(sum);
        if (!csum)
            csum = 0xffff;
        
        udp->check = csum;

    }  
    
    void
    setLengthsAndIPChecksum(data_iterator b, data_iterator e)
    {
        iphdr* ip = reinterpret_cast<iphdr*>(&*b);
        ip->tot_len = rohc_htons(static_cast<uint16_t>(e-b));
        if (ip->protocol == 17)
        {
            udphdr* udp = reinterpret_cast<udphdr*>(ip+1);
            udp->len = rohc_htons(static_cast<uint16_t>(e - b - sizeof(iphdr)));
        }
        
        calculateIpHeaderCheckSum(ip);
    }
    
    void PrintHeaders(std::vector<uint8_t>::const_iterator iph)
    {
        const iphdr* ip = reinterpret_cast<const iphdr*>(&*iph);
        PrintIPHeader(ip);
        if (17 == ip->protocol)
        {
            const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
            PrintUDPHeader(udp);
        }
    }
    
    void PrintIPHeader(const_data_iterator iph)
    {
        PrintIPHeader(reinterpret_cast<const iphdr*>(&*iph));
    }
    
    void PrintIPHeader(const iphdr* ip)
    {
        cout << "IP header:" << endl;
        cout << "+-------------------------------+" << endl;
        char buf[200];
        
        snprintf(buf, sizeof(buf), "|%2hd |%2hd |  0x%02hx |     %5hu     | (v, hl, tos, len)",
                               (short)ip->version,
                               (short)ip->ihl,
                               (unsigned short)ip->tos,
                               (unsigned short)rohc_htons(ip->tot_len));
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        snprintf(buf, sizeof(buf), "|    %5hu      |%hu%hu%hu|    %4hu   | (id, flags, offset)",
                               (unsigned short)rohc_htons(ip->id),
                               (unsigned short)(rohc_htons(ip->frag_off) >> 15 & 1),
                               (unsigned short)(rohc_htons(ip->frag_off) >> 14 & 1),
                               (unsigned short)(rohc_htons(ip->frag_off) >> 13 & 1),
                               (unsigned short)(rohc_htons(ip->frag_off) & 0x1f));
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        snprintf(buf, sizeof(buf), "|  %3hu  |  %3hu  |    0x%04hx     | (ttl, proto, chksum)",
                               (unsigned short)ip->ttl,
                               (unsigned short)ip->protocol,
                               rohc_htons(ip->check));
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        const unsigned char* paddr = reinterpret_cast<const unsigned char*>(&ip->saddr);
        snprintf(buf, sizeof(buf), "|  %3hu  |  %3hu  |  %3hu  |  %3hu  | (src)",
                               (unsigned short)paddr[0],
                               (unsigned short)paddr[1],
                               (unsigned short)paddr[2],
                               (unsigned short)paddr[3]);
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        paddr = reinterpret_cast<const unsigned char*>(&ip->daddr);
        snprintf(buf, sizeof(buf), "|  %3hu  |  %3hu  |  %3hu  |  %3hu  | (dest)",
                 (unsigned short)paddr[0],
                 (unsigned short)paddr[1],
                 (unsigned short)paddr[2],
                 (unsigned short)paddr[3]);
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
    }
    
    void PrintUDPHeader(const udphdr* udp)
    {
        cout << "UDP header:" << endl;
        char buf[200];
        cout << "+-------------------------------+" << endl;
        snprintf(buf, sizeof(buf), "|     %5hu     |     %5hu     | (src port, dest port)\n",
                 rohc_htons(udp->source), rohc_htons(udp->dest));
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        snprintf(buf, sizeof(buf), "|     %5hu     |     0x%04hx    | (len, chksum)\n",
                                rohc_htons(udp->len), rohc_htons(udp->check));
        cout << buf << endl;
        cout << "+-------------------------------+" << endl;
        
    }
} // ns ROHC
