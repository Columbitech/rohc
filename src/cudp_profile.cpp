#include <algorithm>

#include "cudp_profile.h"
#include "network.h"
#include <rohc/compressor.h>
//#include <iostream>
#include <iterator>

using namespace std;
namespace ROHC
{
    /**************************************************************************
     * Compression Profile
     **************************************************************************/
    
    CUDPProfile::CUDPProfile(Compressor* comp, uint16_t cid, const iphdr* ip)
    : CProfile(comp, cid, ip),
    sport(0),
    dport(0),
    checksum_used(true)
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip + 1);
        sport = udp->source;
        dport = udp->dest;
        checksum_used = udp->check != 0;
    }
    
    bool
    CUDPProfile::Matches(unsigned int profileID, const ROHC::iphdr *ip) const
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
        return (profileID == ID()) &&
            (saddr == ip->saddr) &&
            (sport == udp->source) &&
            (daddr == ip->daddr) &&
            (dport == udp->dest);
    }
    
    void
    CUDPProfile::Compress(const data_t& data, data_t& output)
    {
        size_t outputInSize = output.size();
        const iphdr* ip = reinterpret_cast<const iphdr*>(&data[0]);
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
                
        UpdateIpIdOffset(ip);
        
        if (IR_State == state)
        {
            CreateIR(ip, udp, output);
        }
        else
        {
            CreateCO(ip, udp, output);
        }
        
        UpdateIpInformation(ip);
        
        AdvanceState(false, false);
        increaseMsn();
        // Append payload
        output.insert(output.end(), data.begin() + sizeof(iphdr) + sizeof(udphdr), data.end());
        
        ++numberOfPacketsSent;
        dataSizeCompressed += output.size() - outputInSize;
        dataSizeUncompressed += data.size();
    }
    
    void
    CUDPProfile::CreateIR(const iphdr* ip, const udphdr* udp, data_t &output)
    {
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
        
        create_udp_static(sport, dport, output);
        
        create_ipv4_regular_innermost_dynamic(ip, output);
        
        create_udp_endpoint_dynamic(msn, reorder_ratio, udp, output);
        
        // Calculate CRC
        uint8_t crc = CRC8(output.begin() + headerStartIdx, output.end());
        output[crcPos] = crc;

		IncreasePacketCount(PT_IR);
        
        ++numberOfIRPacketsSent;
        ++numberOfIRPacketsSinceReset;
    }
    
    /*
     COMPRESSED udp_static {
     src_port =:= irregular(16) [ 16 ];
     dst_port =:= irregular(16) [ 16 ];
     }
     */
    void
    CUDPProfile::create_udp_static(uint16_t sport, uint16_t dport, data_t &output)
    {
        AppendData(output, sport);
        AppendData(output, dport);
    }
    
    /*
     COMPRESSED udp_endpoint_dynamic {
     ENFORCE(profile_value == PROFILE_UDP_0102);
     ENFORCE(profile == PROFILE_UDP_0102);
     ENFORCE(checksum_used.UVALUE == (checksum.UVALUE != 0));
     checksum       =:= irregular(16)           [ 16 ];
     msn            =:= irregular(16)           [ 16 ];
     reserved       =:= compressed_value(6, 0)  [ 6 ];
     reorder_ratio  =:= irregular(2)            [ 2 ];
     }
     */
    void
    CUDPProfile::create_udp_endpoint_dynamic(uint16_t msn, Reordering_t reorder_ratio, const udphdr* udp, data_t &output)
    {
        const uint8_t* p8 = reinterpret_cast<const uint8_t*>(&udp->check);
        output.insert(output.end(), p8, p8 + sizeof(udp->check));
        AppendDataToNBO(output, msn);
        output.push_back(static_cast<uint8_t>(reorder_ratio));
    }
        
    /*
      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
     : Add-CID octet                 : if for small CIDs and CID 1-15
     +---+---+---+---+---+---+---+---+
     | first octet of base header    | (with type indication)
     +---+---+---+---+---+---+---+---+
     :                               :
     / 0, 1, or 2 octets of CID / 1-2 octets if large CIDs
     :                               :
     +---+---+---+---+---+---+---+---+
     / remainder of base header      / variable length
     +---+---+---+---+---+---+---+---+
     :                               :
     / Irregular Chain               / variable length
     :                               :
     --- --- --- --- --- --- --- ---
     */
    
    void
    CUDPProfile::CreateCO(const ROHC::iphdr *ip, const ROHC::udphdr *udp, data_t &output)
    {
        data_t baseheader;
        
        unsigned int neededMSNWidth = msnWindow.width(msn);
        
		bool basic = (SO_State == state) && !TOSChanged(ip) && !TTLChanged(ip) && !DFChanged(ip);

		bool pt_0_crc3_possible = basic && (neededMSNWidth <= 4);
		bool pt_0_crc7_possible = basic && (neededMSNWidth <= 6);

		if ((IP_ID_BEHAVIOUR_RANDOM == ip_id_behaviour) ||
				 (IP_ID_BEHAVIOUR_ZERO == ip_id_behaviour))
		{
			if (pt_0_crc3_possible)
			{
				create_pt_0_crc3(baseheader);
			}
			else if (pt_0_crc7_possible)
			{
				create_pt_0_crc7(baseheader);
			}
			else
			{
				create_co_common(ip, baseheader);
			}
		}
		else
		{
			unsigned int neededIPIDWidth = IpIdOffsetWidth();

			pt_0_crc3_possible = pt_0_crc3_possible && !IPIDOffsetChanged();
			pt_0_crc7_possible = pt_0_crc7_possible && !IPIDOffsetChanged();
			bool pt_1_seq_id_possible = basic && (neededMSNWidth <=6) && (neededIPIDWidth <= 4);
			bool pt_2_seq_id_possible = basic && (neededMSNWidth <= 8) && (neededIPIDWidth <= 6);


			// TODO
			// the pt_0 can only be used if the last IP only differs by
			// one from this IP id.

			if (pt_0_crc3_possible)
			{
				create_pt_0_crc3(baseheader);
			}
			else if (pt_0_crc7_possible)
			{
				create_pt_0_crc7(baseheader);
			}
			else if (pt_1_seq_id_possible)
			{
				create_pt_1_seq_id(baseheader);
			}
			else if (pt_2_seq_id_possible)
			{
				create_pt_2_seq_id(baseheader);
			}
			else
			{
				create_co_common(ip, baseheader);
			}
		}

        if (!largeCID && cid)
        {
            output.push_back(CreateShortCID(cid));
        }
        
        output.push_back(baseheader[0]);
        
        if (largeCID)
        {
            SDVLEncode(back_inserter(output), cid);
        }
        
        output.insert(output.end(), baseheader.begin() + 1, baseheader.end());
        
        create_ipv4_innermost_irregular(ip, output);
        if (checksum_used) {
            create_udp_with_checksum_irregular(udp, output);
        }
        
        if (FO_State == state) {
            ++numberOfFOPacketsSent;
            ++numberOfFOPacketsSinceReset;
        }
        else {
            ++numberOfSOPacketsSent;
        }
    }
    
    /*
     co_common: This format can be used to update the context when the
     established change pattern of a dynamic field changes, for any of
     the dynamic fields. However, not all dynamic fields are updated
     by conveying their uncompressed value; some fields can only be
     transmitted using a compressed representation. This format is
     especially useful when a rarely changing field needs to be
     updated. This format contains a set of flags to indicate what
     fields are present in the header, and its size can vary
     accordingly. This format is protected by a 7-bit CRC. It can
     update control fields, and it thus also carries a 3-bit CRC to
     protect those fields. This format is similar in purpose to the
     UOR-2-extension 3 format of [RFC3095].
     
     
     // Replacement for UOR-2-ext3
     COMPRESSED co_common {
     ENFORCE(outer_ip_flag == outer_ip_indicator.CVALUE);
     discriminator          =:= ’1111 1010’                     [ 8 ];
     ip_id_indicator        =:= irregular(1)                    [ 1 ]; // see ip_id_sequential_variable
     header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)             [ 7 ];
     flags_indicator        =:= irregular(1)                    [ 1 ];
     ttl_hopl_indicator     =:= irregular(1)                    [ 1 ];
     tos_tc_indicator       =:= irregular(1)                    [ 1 ];
     reorder_ratio          =:= irregular(2)                    [ 2 ];
     control_crc3           =:= control_crc3_encoding           [ 3 ];
     outer_ip_indicator : df : ip_id_behavior_innermost =:=
        profile_2_3_4_flags_enc(
        flags_indicator.CVALUE, ip_version.UVALUE)              [ 0, 8 ];
     tos_tc =:= static_or_irreg(tos_tc_indicator.CVALUE, 8)     [ 0, 8 ];
     ttl_hopl =:= static_or_irreg(ttl_hopl_indicator.CVALUE,
        ttl_hopl.ULENGTH)                                       [ 0, 8 ];
     msn =:= msn_lsb(8)                                         [ 8 ];
     ip_id =:= ip_id_sequential_variable(ip_id_behavior_innermost.UVALUE,
        ip_id_indicator.CVALUE)                                 [ 0, 8, 16 ];
     }
     */
    
    void
    CUDPProfile::create_co_common(const ROHC::iphdr *ip, data_t &baseheader)
    {
		IncreasePacketCount(PT_CO_COMMON);
        baseheader.reserve(9);
        
        baseheader.push_back(0xfa);
        const size_t crcIndex = 1;
        
        bool ip_id_indicator = (ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED) &&
            (IpIdOffsetWidth() > 8);
		if (ip_id_indicator)
        {
            baseheader.push_back(0x80); // ip_id_indicator = 1, crc7 = 0            
        }
        else
        {
            baseheader.push_back(0x00); // ip_id_indicator = 0, crc7 = 0   
        }
        
        uint8_t flags = 0x00; 
        // TODO, check if df or ip_id_behaviour has changed since last!
        bool flags_indicator = DFChanged(ip);
		if (flags_indicator)
        {
            flags |= 0x80;
        }
        
        bool ttl_hopl_indicator = TTLChanged(ip);
        if (ttl_hopl_indicator)
        {
            flags |= 0x40;
        }
        
        bool tos_tc_indicator = TOSChanged(ip);
        if (tos_tc_indicator)
        {
            flags |= 0x20;
        }
        
        flags |= static_cast<uint8_t>((reorder_ratio & 3) << 3); // add reorder_ratio;
        flags |= static_cast<uint8_t>(control_crc3() & 7); // control crc
        baseheader.push_back(flags);
        
        profile_2_3_4_flags_enc(flags_indicator, ip, baseheader);
        
        if (tos_tc_indicator)
        {
            baseheader.push_back(ip->ttl);
        }
        
        if (ttl_hopl_indicator)
        {
            baseheader.push_back(ip->tos);
        }
        
        baseheader.push_back(static_cast<uint8_t>(msn));
        
        ip_id_sequential_variable(ip_id_indicator, ip, baseheader);
        
        //cout << "create_co_common, header size: " << baseheader.size() << endl;
        
        uint8_t crc7 = CRC7(baseheader.begin(), baseheader.end());

        // Save ip_id_indicator
        baseheader[crcIndex] |= static_cast<uint8_t>(crc7 & 0x7f);
    }
    
    /*
     co_repair: This format can be used to update the context of all
     the dynamic fields by conveying their uncompressed value. This is
     especially useful when context damage is assumed (e.g., from the
     reception of a NACK) and a context repair is performed. This
     format is protected by a 7-bit CRC. It also carries a 3-bit CRC
     over the control fields that it can update. This format is
     similar in purpose to the IR-DYN format of [RFC3095] when
     performing context repairs.
     */
    void
    CUDPProfile::create_co_repair(ROHC::iphdr const *ip, ROHC::udphdr const *udp, data_t &output)
    {
        (void)ip;
	(void)udp;
	(void)output;
    }
    
    /*
     pt_0_crc3: This format conveys only the MSN; it can therefore only
     update the MSN and fields that are derived from the MSN, such as
     IP-ID and the RTP Timestamp (for applicable profiles). It is
     protected by a 3-bit CRC. This format is equivalent to the UO-0
     header format in [RFC3095].
     
     // UO-0
     COMPRESSED pt_0_crc3 {
         discriminator =:= ’0’ [ 1 ];
         msn =:= msn_lsb(4) [ 4 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH) [ 3 ];
         ip_id =:= inferred_sequential_ip_id [ 0 ];
     }
     */
    void
    CUDPProfile::create_pt_0_crc3(data_t &output)
    {
		IncreasePacketCount(PT_0_CRC3);
        uint8_t data = static_cast<uint8_t>((msn & 0x0f) << 3);
        output.push_back(data);
        uint8_t crc3 = CRC3(output.end() - 1, output.end());
        *output.rbegin() |= crc3;
    }
    
    /*
     pt_0_crc7: This format has the same properties as pt_0_crc3, but
     is instead protected by a 7-bit CRC and contains a larger amount
     of lsb-encoded MSN bits. This format is useful in environments
     where a high amount of reordering or a high-residual error rate
     can occur.
     
     // New format, Type 0 with strong CRC and more SN bits
     COMPRESSED pt_0_crc7 {
         discriminator =:= ’100’ [ 3 ];
         msn =:= msn_lsb(6) [ 6 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH) [ 7 ];
         ip_id =:= inferred_sequential_ip_id [ 0 ];
     }
     */
    void 
    CUDPProfile::create_pt_0_crc7(data_t &output)
    {
		IncreasePacketCount(PT_0_CRC7);
        uint8_t lsbMsn = static_cast<uint8_t>(msn & 0x3f); // lower 6 bits
        uint8_t discriminator_MsbMSN = static_cast<uint8_t>(0x80 | (lsbMsn >> 1));
        output.push_back(discriminator_MsbMSN);
        uint8_t lsbMsn_crc7 = static_cast<uint8_t>(lsbMsn << 7);
        output.push_back(lsbMsn_crc7);
        uint8_t crc7 = CRC7(output.end() - 2, output.end());
        *output.rbegin() |= crc7;
    }
    
    /*
     pt_1_seq_id: This format can convey changes to the MSN and to the
     IP-ID. It is protected by a 7-bit CRC. It is similar in purpose
     to the UO-1-ID format in [RFC3095].
     
     
     // UO-1-ID replacement (PT-1 only used for sequential)
     COMPRESSED pt_1_seq_id {
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL) ||
                 (ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’101’ [ 3 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH) [ 3 ];
         msn =:= msn_lsb(6) [ 6 ];
         ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 4) [ 4 ];
     }
     */
    
    void
    CUDPProfile::create_pt_1_seq_id(data_t &output)
    {
		IncreasePacketCount(PT_1_SEQ_ID);
        uint8_t lsbMsn = static_cast<uint8_t>(msn & 0x3f); // lower 6 bits
        
        uint8_t disc_crc_msn = static_cast<uint8_t>(0xa0 + (lsbMsn >> 4));
        output.push_back(disc_crc_msn);
        uint8_t msn_ip_id = static_cast<uint8_t>(lsbMsn << 4);

		msn_ip_id |= static_cast<uint8_t>(IpIdOffset() & 0x0f); 
        
        output.push_back(msn_ip_id);
        uint8_t crc3 = CRC3(output.end() - 2, output.end());
        *(output.rbegin() + 1) |= crc3 << 2;
    }
    
    
    /*
     pt_2_seq_id: This format can convey changes to the MSN and to the
     IP-ID. It is protected by a 7-bit CRC. It is similar in purpose
     to the UO-2-ID format in [RFC3095].
     
     
     // UOR-2-ID replacement
     COMPRESSED pt_2_seq_id {
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL) ||
                 (ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’110’ [ 3 ];
         ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 6) [ 6 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH) [ 7 ];
         msn =:= msn_lsb(8) [ 8 ];
     }     
     */
    void
    CUDPProfile::create_pt_2_seq_id(data_t &output)
    {
		IncreasePacketCount(PT_2_SEQ_ID);
        RASSERT(ip_id_behaviour == IP_ID_BEHAVIOUR_SEQUENTIAL ||
                ip_id_behaviour == IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED);

		uint8_t lsb_ip_id = IpIdOffset() & 0x3f; // 6 bits
        output.push_back(0xc0 | lsb_ip_id >> 1);
        output.push_back(lsb_ip_id << 7); // crc 0 for now and 1 lsb bit from id
        output.push_back(static_cast<uint8_t>(msn));
        uint8_t crc7 = CRC7(output.end() - 3, output.end());
        *(output.rbegin() + 1) = crc7 | (lsb_ip_id << 7);
    }
        
    uint8_t
    CUDPProfile::control_crc3() const
    {
        data_t data;
        // reorder_ratio, 2 bits padded with 6 MSB of zeroes
        data.push_back(static_cast<uint8_t>(reorder_ratio) & 3);
        AppendDataToNBO(data, msn);
        data.push_back(static_cast<uint8_t>(ip_id_behaviour) & 3);
        uint8_t crc3 = CRC3(data.begin(), data.end());
        return crc3;
    }
    
    
    /*
     profile_2_3_4_flags_enc(flag, ip_version)
     {
         UNCOMPRESSED {
             ip_outer_indicator [ 1 ];
             df [ 0, 1 ];
             ip_id_behavior [ 2 ];
         }
         COMPRESSED not_present {
             ENFORCE(flag == 0);
             ENFORCE(ip_outer_indicator.CVALUE == 0);
             df =:= static;
             ip_id_behavior =:= static;
         }
         COMPRESSED present {
             ENFORCE(flag == 1);
             ip_outer_indicator =:= irregular(1) [ 1 ];
             df =:= dont_fragment(ip_version) [ 1 ];
             ip_id_behavior =:= irregular(2) [ 2 ];
             reserved =:= compressed_value(4, 0) [ 4 ];
         }
     }
     */
    void
    CUDPProfile::profile_2_3_4_flags_enc(bool flag, const iphdr* ip, data_t &output)
    {
        if (flag)
        {
            uint8_t res = 0x00; // ip_outer_indicator = 0
            if (HasDontFragment(ip))
            {
                res |= 0x40;
            }
            
            res |= static_cast<uint8_t>((ip_id_behaviour << 4) & 0x30);
            
            RASSERT((res & 0x0f) == 0);
            output.push_back(res);
        }
    }
        
    void
    CUDPProfile::create_udp_with_checksum_irregular(const ROHC::udphdr *udp, data_t &output)
    {
        AppendData(output, udp->check);
    }

	void CUDPProfile::MsnWasAcked(uint16_t /*ackMSN*/) {
		AdvanceState(true, true);
	}

	void CUDPProfile::NackMsn(uint16_t msn) {
		AckFBMsn(msn);
		numberOfIRPacketsSinceReset = numberOfFOPacketsSinceReset = 0;
		state = IR_State;
	}

	void CUDPProfile::StaticNackMsn(uint16_t msn) {
		NackMsn(msn);
	}
    
    void
    CUDPProfile::AdvanceState(bool calledFromFeedback, bool ack)
    {
        if (IR_State == state)
        {
            // If we received
            if (calledFromFeedback && ack)
            {
                state = FO_State;
            }
            else if (numberOfIRPacketsSinceReset >= compressor->NumberOfIRPacketsToSend())
                state = FO_State;
        }
        else if (FO_State == state)
        {
            if (calledFromFeedback && ack)
            {
                state = SO_State;
            }
            else if (numberOfFOPacketsSinceReset >= compressor->NumberOfFOPacketsToSend())
                state = SO_State;
            
        }
        else if (SO_State == state)
        {
            
        }
    }
} // ns ROHC
