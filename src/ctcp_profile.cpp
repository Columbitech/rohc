#include "ctcp_profile.h"
#include "tcp_profile_supp.h"

namespace ROHC {
    CTCPProfile::CTCPProfile(Compressor* comp, uint16_t cid, const iphdr* ip) 
    : CProfile(comp, cid, ip) {
        
    }
    
    bool CTCPProfile::Matches(unsigned int profileID, const ROHC::iphdr *ip) const {
        if (profileID != ProfileID()) {
            return false;
        }
        
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(ip + 4*ip->ihl);

        return (ProtocolID() == ip->protocol) &&
            (saddr == ip->saddr) &&
            (daddr == ip->daddr) &&
            (last_tcp.source == tcp->source) &&
            (last_tcp.dest == tcp->dest);
    }
    
    void CTCPProfile::MsnWasAcked(uint16_t /*ackedMSN*/) {
        
    }
    
    void CTCPProfile::NackMsn(uint16_t /*fbMSN*/) {
        
    }
    
    void CTCPProfile::StaticNackMsn(uint16_t /*fbMSN*/) {
        
    }
    
    void CTCPProfile::Compress(const data_t &data, data_t &output) {
        size_t outputInSize = output.size();
        const iphdr* ip = reinterpret_cast<const iphdr*>(&data[0]);
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(ip+ip->ihl*4);
        
        UpdateIpIdOffset(ip);
        
        if (IR_State == state)
        {
            CreateIR(ip, tcp, output);
        }
        else
        {
            CreateCO(ip, tcp, output);
        }
        
        UpdateIpInformation(ip);
        
        AdvanceState(false, false);
        increaseMsn();
        // Append payload
        // TODO, handle TCP options
        output.insert(output.end(), data.begin() + sizeof(iphdr) + sizeof(tcphdr), data.end());
        
        ++numberOfPacketsSent;
        dataSizeCompressed += output.size() - outputInSize;
        dataSizeUncompressed += data.size();
        
    }
    
    void CTCPProfile::CreateIR(const ROHC::iphdr *ip, const ROHC::tcphdr *tcp, data_t &output) {
        size_t headerStartIdx = output.size();
        
        if (!largeCID && cid)
        {
            output.push_back(CreateShortCID(cid));
        }
        
        output.push_back(IRv2Packet);
        
        if (largeCID)
        {
            SDVLEncode(back_inserter(output), cid);
        }
        
        output.push_back(static_cast<uint8_t>(ProfileID()));
        
        size_t crcPos = output.size();
        
        // Add zero crc for now
        output.push_back(0);
        
        create_ipv4_static(ip, output);
        
        create_tcp_static(tcp, output);
        
        create_ipv4_regular_innermost_dynamic(ip, output);
        
        //create_tcp_dynamic(msn, reorder_ratio, udp, output);
        
        // Calculate CRC
        uint8_t crc = CRC8(output.begin() + headerStartIdx, output.end());
        output[crcPos] = crc;
        
		IncreasePacketCount(PT_IR);
        
        ++numberOfIRPacketsSent;
        ++numberOfIRPacketsSinceReset;
    }
    
    void CTCPProfile::CreateCO(const ROHC::iphdr */*ip*/, const ROHC::tcphdr */*tcp*/, data_t &/*output*/) {
        
    }
    
    void CTCPProfile::AdvanceState(bool /*calledFromFeedback*/, bool /*ack*/) {
        
    }
    
    void CTCPProfile::create_tcp_static(const ROHC::tcphdr *tcp, data_t &output) {
        AppendData(output, tcp->source);
        AppendData(output, tcp->dest);
    }
    
    /**
     COMPRESSED tcp_dynamic {
     ecn_used =:= one_bit_choice [ 1 ];
     ack_stride_flag =:= irregular(1) [ 1 ];
     ack_zero =:= irregular(1) [ 1 ];
     urp_zero =:= irregular(1) [ 1 ];
     tcp_res_flags =:= irregular(4) [ 4 ];
     tcp_ecn_flags =:= irregular(2) [ 2 ];
     urg_flag =:= irregular(1) [ 1 ];
     ack_flag =:= irregular(1) [ 1 ];
     psh_flag =:= irregular(1) [ 1 ];
     rsf_flags =:= irregular(3) [ 3 ];
     msn =:= irregular(16) [ 16 ];
     seq_number =:= irregular(32) [ 32 ];
     ack_number =:=
       zero_or_irreg(ack_zero.CVALUE, 32) [ 0, 32 ];
     window =:= irregular(16) [ 16 ];
     checksum =:= irregular(16) [ 16 ];
     urg_ptr =:=
       zero_or_irreg(urp_zero.CVALUE, 16) [ 0, 16 ];
     ack_stride =:=
       static_or_irreg(ack_stride_flag.CVALUE, 16) [ 0, 16 ];
     options =:= list_tcp_options [ VARIABLE ];
     }
     
     */
    
    void CTCPProfile::create_tcp_dynamic(const ROHC::tcphdr *tcp, data_t &output) {
        uint8_t ecn_ackStride_ackZero_urpZero_res  = 0;
        
        // ecn_used
        if (tcp->ECE) {
            ecn_ackStride_ackZero_urpZero_res |= 0x80;
        }
        
        // ack_stride_flag
        
        // ack_zero
        if (tcp->ACK && tcp->ackNumber) {
            ecn_ackStride_ackZero_urpZero_res |= 0x20;
        }
        
        // urp_zero
        if (tcp->URG && tcp->urgPtr) {
            ecn_ackStride_ackZero_urpZero_res |= 0x10;
        }
        
        ecn_ackStride_ackZero_urpZero_res |= tcp->reserved;
        
        output.push_back(ecn_ackStride_ackZero_urpZero_res);
        
        AppendData(output, msn);
        AppendData(output, tcp->sequenceNumber);
        
        if (tcp->ACK && tcp->ackNumber) {
            AppendData(output, tcp->ackNumber);
        }
        
        AppendData(output, tcp->windowSize);

        AppendData(output, tcp->check);
        
        if (tcp->URG && tcp->urgPtr) {
            AppendData(output, tcp->urgPtr);
        }
    }
}
