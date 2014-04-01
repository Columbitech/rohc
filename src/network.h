#pragma once

#include <stdint.h>
#include <rohc/rohc.h>
#include <vector>

namespace ROHC {
    
    struct iphdr
    {
        uint8_t ihl:4,
                version:4
                ;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };
    
    inline bool HasDontFragment(const iphdr* ip) {
        // TODO: Little/big endian fix
        return (ip->frag_off & 0x0040) != 0;
    }
    
    inline void SetDontFragment(iphdr* ip) {
        // TODO: Little/big endian fix
        ip->frag_off |= 0x0040;
    }
    
    inline void ClearDontFragment(iphdr* ip) {
        // TODO: Little/big endian fix
        ip->frag_off &= 0xffbf;
    }

    inline bool HasMoreFragments(iphdr const* ip) {
        // TODO: Little/big endian fix
        return (ip->frag_off & 0x0020) != 0;
    }   

    inline bool HasFragmentOffset(iphdr const* ip) {
        // TODO: Little/big endian fix
        return (ip->frag_off & 0xff1f) != 0;
    }   

    struct udphdr
    {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
        static uint8_t ipproto() {return 17;}
    };
    
    struct rtphdr
    {
        uint8_t csrc_count:4,
        extension:1,
        padding:1,
        version:2;
        uint8_t payload_type: 7,
            marker:1;
        uint16_t sequence_number;
        uint32_t timestamp;
        uint32_t ssrc;
    };
    
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t sequenceNumber;
        uint32_t ackNumber;
        uint8_t dataOffset:4,
                reserved:3,
                NS:1;
        uint8_t CWR:1,
                ECE:1,
                URG:1,
                ACK:1,
                PSH:1,
                RST:1,
                SYN:1,
                FIN:1;
        uint16_t windowSize;
        uint16_t check;
        uint16_t urgPtr;
    };
    
    
    void setLengthsAndIPChecksum(data_iterator b, data_iterator e);
    void calculateIpHeaderCheckSum(iphdr* iph);
    void calculateUdpHeaderCheckSum(iphdr* ip);    
    
    void PrintHeaders(std::vector<uint8_t>::const_iterator ip);
    void PrintIPHeader(std::vector<uint8_t>::const_iterator ip);
    void PrintIPHeader(const iphdr* ip);
    void PrintUDPHeader(const udphdr* udp);

    inline uint16_t rohc_htons(uint16_t v) 
    {
        return static_cast<uint16_t>((v << 8) | (v >> 8));
    }

    inline uint32_t rohc_htonl(uint32_t v)
    {
        uint8_t* p = reinterpret_cast<uint8_t*>(&v);
        return (p[0] << 24) + (p[1] << 16) + (p[2] << 8) + p[3];
    }
    
} // ns ROHC
