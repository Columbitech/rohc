#include <algorithm>

#include "dudp_profile.h"
#include "network.h"
#include <rohc/compressor.h>
#include <rohc/decomp.h>
#include <cassert>

using namespace std;
namespace ROHC
{
    DUDPProfile::DUDPProfile(Decompressor* decomp, uint16_t cid)
    : DProfile(decomp, cid)
    , checksum_used(false)
    ,udp()
    {
    }
    
    void
    DUDPProfile::MergeGlobalControlAndAppendHeaders(const ROHC::global_control &gc, data_t &output)
    {
        state = FULL_CONTEXT;
        
        ++numberofIRPackets;
        ++numberOfPacketsReceived;
        
        msn = gc.msn;
        SetReorderRatio(gc.reorder_ratio);
        ip_id_behaviour = gc.ip_id_behaviour;
        checksum_used = gc.udp_checksum_used;
        ip = gc.ip;
        udp = gc.udp;

		UpdateIPIDOffsetFromID();
        
        AppendData(output, ip);
        AppendData(output, udp);
        SendFeedback1();
    }
        
    bool
    DUDPProfile::ParseIR(global_control& gc, const data_t& data, const_data_iterator& pos)
    {
        const_data_iterator end(data.end());
        if(!DProfile::parse_ipv4_static(gc, pos, end))
            return false;
        if(!parse_udp_static(gc, pos, end))
            return false;
        
        if(!DProfile::parse_ipv4_regular_innermost_dynamic(gc, pos, end))
            return false;
        
        if(!parse_udp_endpoint_dynamic(gc, pos, end))
            return false;

        return true;
    }
        
    bool
    DUDPProfile::parse_udp_endpoint_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator& end)
    {
        if(!GetValue(pos, end, gc.udp.check)) {
            error("parse_udp_endpoint_dynamic, failed to get udp checksum\n");
            return false;
        }
        gc.udp_checksum_used = gc.udp.check != 0;
        
        if (!GetValueFromNBO(pos, end, gc.msn)) {
            error("parse_udp_endpoint_dynamic, failed to get MSN\n");
            return false;
        }
        
        if (std::distance(pos, end) < 1) {
            error("parse_udp_endpoint_dynamic - not enough data for reorder ratio");
            return false;
        }
        uint8_t reserved_reorderRatio = *pos++;
        
        if(!((reserved_reorderRatio & 0xfc) == 0)) {
            error("parse_udp_endpoint_dynamic, not a valid RR\n");
            return false;
        }
        
        gc.reorder_ratio = static_cast<Reordering_t>(reserved_reorderRatio & 3);
        return true;
    }
    
    
    /*
       0   1   2   3   4   5   6   7
      --- --- --- --- --- --- --- ---
     : Add-CID octet                 : if for small CIDs and CID 1-15
     +---+---+---+---+---+---+---+---+
     | first octet of base header    | (with type indication)
     +---+---+---+---+---+---+---+---+
     :                               :
     / 0, 1, or 2 octets of CID      / 1-2 octets if large CIDs
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
    DUDPProfile::ParseCO(uint8_t packetTypeIndication, data_t &data, data_iterator pos, data_t &output)
    {
		if (FULL_CONTEXT != state) {
			decomp->SendStaticNACK(cid, msn);
		}
        // pos will point at remainder of base header
        data_iterator posMinusOne = pos - 1;
        pos = posMinusOne;
        
        
        // Make first octet of base header adjacent to the remainder
        uint8_t stored = 0;
        if (largeCID)
        {
            stored = *posMinusOne;
            *posMinusOne = packetTypeIndication;
        }
        
        if (0xfa == packetTypeIndication)
        {
            if(!parse_co_common(pos, data.end())) 
                return;
        }
        else if (0x80 == (packetTypeIndication & 0xe0))
        {
            if(!parse_pt_0_crc7(pos, data.end())) 
                return;
        }
        else if (0 == (packetTypeIndication & 0x80))
        {
            if(!parse_pt_0_crc3(pos, data.end())) 
                return;
        }
        else if(0xa0 == (packetTypeIndication & 0xe0))
        {
            if(!parse_pt_1_seq_id(pos, data.end())) 
                return;
        }
        else if (0xc0 == (packetTypeIndication & 0xe0))
        {
            if(!parse_pt_2_seq_id(pos, data.end())) 
                return;
        }
        else
        {
            error("Unknown base header type: %x\n", (unsigned) packetTypeIndication);
            return;
        }
        if (data.end() == pos)
        {
            return;
        }

        if (largeCID)
        {
            *posMinusOne = stored;
        }
                
		if(!parse_ipv4_innermost_irregular(pos, data.end())) {
            return;
        }
        
        // udp irreg
        if (checksum_used)
        {
            if(!GetValue(pos, data.end(), udp.check)) {
                error("ParseCO, cannot get udp checksum\n");
                return;
            }
        }
        
        
        // Append payload
        size_t ipIdx = output.size();
        AppendData(output, ip);
        AppendData(output, udp);
        output.insert(output.end(), pos, data.end());
        iphdr* pip = reinterpret_cast<iphdr*>(&output[ipIdx]);
        pip->tot_len = rohc_htons(static_cast<uint16_t>(output.size()));
        udphdr* pudp = reinterpret_cast<udphdr*>(pip+1);
        pudp->len = rohc_htons(static_cast<uint16_t>(output.size() - sizeof(iphdr)));
        calculateIpHeaderCheckSum(pip);
        SendFeedback1();
    }
    
    void
    DUDPProfile::ParseCORepair(const data_t& /*data*/, const_data_iterator r2_crc3_pos, data_t& /*output*/)
    {
        const_data_iterator pos = r2_crc3_pos;
        uint8_t r2_crc3 = *pos++;
        
        if (r2_crc3 & 0xf8)
        {
            // TODO: Send NACK
            return;
        }
        
		/*
        if (r2_crc3 != (control_crc3() & 3))
        {
            // TODO: Send NACK
            return;
        }
        
		*/
        // TODO fix me
        //        pos = parse_ipv4_regular_innermost_dynamic(pos);
        //pos = parse_udp_endpoint_dynamic(pos);
        
    }
    
    bool
    DUDPProfile::parse_udp_static(ROHC::global_control &gc, const_data_iterator& pos, const_data_iterator& end)
    {
      //RASSERT((data.end() - pos) >= 4);
        if (!GetValue(pos, end, gc.udp.source)) {
            error("parse_udp_static, udp source\n");
            return false;
        }
        if(!GetValue(pos, end, gc.udp.dest)) {
            error("parse_udp_static, udp dest\n");
            return false;
        }
        return true;
    }
    
    uint8_t
    DUDPProfile::control_crc3(Reordering_t newRR, uint16_t new_msn, IPIDBehaviour_t new_ip_id_behaviour) const
    {
        data_t data;
        // reorder_ratio, 2 bits padded with 6 MSB of zeroes
        data.push_back(static_cast<uint8_t>(newRR) & 3);

        AppendDataToNBO(data, new_msn);

        data.push_back(static_cast<uint8_t>(new_ip_id_behaviour) & 3);
        
        uint8_t crc3 = CRC3(data.begin(), data.end());
        return crc3;
    }

    /*
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
    bool
    DUDPProfile::parse_co_common(data_iterator& pos, const data_iterator& end)
    {
        if ((end - pos) < 3) {
            error("parse_co_common, not enough data\n");
            return false;
        }
        data_iterator headerStart = pos;
        // skip discriminator
        if (!(*pos == 0xfa)) {
            error("parse_co_common, wrong header\n");
            return false;
        }
        ++pos;
        
        data_iterator crcPos = pos;
        uint8_t ip_id_indicator_crc7 = *pos++;
        
        bool ip_id_indicator = (ip_id_indicator_crc7 & 0x80) > 0;
        
        uint8_t flags_crc3 = *pos++;

        bool flags_indicator = (flags_crc3 & 0x80) > 0;
        bool ttl_hopl_indicator = (flags_crc3 & 0x40) > 0;
        bool tos_tc_indicator = (flags_crc3 & 0x20) > 0;

        size_t headerSize = pos - headerStart + 1; // add one for msn
        if (flags_indicator)
            ++headerSize;
        if (ttl_hopl_indicator)
            ++headerSize;
        if (tos_tc_indicator)
            ++headerSize;
        
        if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
            IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
        {
            ++headerSize; // short encoding
            if (ip_id_indicator)
                ++headerSize; // long encoding
        }
        
        *crcPos &= 0x80;
        uint8_t calcCRC = CRC7(headerStart, headerStart + headerSize);
        *crcPos = ip_id_indicator_crc7;
                
        if ((ip_id_indicator_crc7 & 0x7f) != calcCRC)
        {
            error("parse_co_common, checksum 7\n");
			SendNack();
            return false;
        }
        
		Reordering_t newRR = static_cast<Reordering_t>((flags_crc3 >> 3) & 3);

		IPIDBehaviour_t newBehaviour = ip_id_behaviour;
		bool dontFragment = false;

		if (flags_indicator)
		{
			if(!parse_profile_2_3_4_flags_enc(pos, end, dontFragment, newBehaviour))
                return false;
		}

		uint8_t newTOS = ip.tos;
        if (tos_tc_indicator)
        {
            if((end - pos) < 1) {
                error("parse_co_common, tos\n");
                return false;
            }
            newTOS = *pos++;
        }

		uint8_t newTTL = ip.ttl;
        if (ttl_hopl_indicator)
        {
            if((end - pos) < 1) {
                error("parse_co_common, ttl\n");
                return false;
            }
			newTTL = *pos++;
        }
        
        if((end - pos) < 1) {
            error("parse_co_common, msn\n");
            return false;
        }
        uint8_t lsbMsn = *pos++;
		uint16_t newMsn;
        UpdateMSN(lsbMsn, 8, newMsn);

		uint16_t new_ip_id_offset = ip_id_offset;
		uint16_t new_ip_id;
        if (!parse_ip_id_sequential_variable(ip_id_indicator, pos, end, new_ip_id_offset, new_ip_id)) {
            return false;
        }

		if ((flags_crc3 & 7) != control_crc3(newRR, newMsn, newBehaviour)) {
            error("parse_co_common, checksum 3, oldMSN: %u, newMSN %u\n", msn, newMsn);
            SendNack();
            return false;
        }

        SetReorderRatio(newRR);

		if (flags_indicator) {
			if (dontFragment) {
				SetDontFragment(&ip);
			}
			else {
				ClearDontFragment(&ip);
			}
		}

		ip_id_behaviour = newBehaviour;
		ip.tos = newTOS;
		ip.ttl = newTTL;

		msn = newMsn;
		if (ip_id_indicator) {
			ip.id = new_ip_id;
			UpdateIPIDOffsetFromID();
		}
		else {
			ip_id_offset = new_ip_id_offset;
			UpdateIPIDFromOffset();
		}
        return true;
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
    bool 
    DUDPProfile::parse_pt_0_crc3(data_iterator& pos, const data_iterator& end)
    {
        if ((end - pos) < 1) {
            error("parse_pt_0_crc3, not enough data\n");
            return false;
        }
        uint8_t d = *pos;
        // clear crc
        *pos &= 0xf8;
        uint8_t calcCRC3 = CRC3(pos, pos+1);
        *pos = d;
        
        if (calcCRC3 != (d&7)) {
            error("parse_pt_0_crc3, checksum\n");
            SendNack();
            return false;
        }
        
        uint8_t lsbMsn = d >> 3;
        uint16_t delta_msn = UpdateMSN(lsbMsn, 4, msn);
        parse_inferred_sequential_ip_id(delta_msn);
        pos+=1;
        return true;
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
    bool
    DUDPProfile::parse_pt_0_crc7(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 2) {
            error("parse_pt_0_crc7, not enough data\n");
            return false;
        }
        uint8_t msbMsn = *pos++;
        uint8_t lsbMsn_crc7 = *pos;
        *pos = lsbMsn_crc7 & 0x80;
        uint8_t calcCRC7 = CRC7(pos - 1, pos + 1);
        if (calcCRC7 != (lsbMsn_crc7 & 0x7f)) {
            SendNack();
            error("parse_pt_0_crc7, crc 7 failure\n");
            return false;
        }
        *pos++ = lsbMsn_crc7;
        uint8_t lsbMsn = (msbMsn << 1) | (lsbMsn_crc7 >> 7);
        uint16_t delta_msn = UpdateMSN(lsbMsn, 6, msn);
        parse_inferred_sequential_ip_id(delta_msn);
        return true;
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
    bool
    DUDPProfile::parse_pt_1_seq_id(data_iterator& pos, const data_iterator& end) {
        if (!((IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
               IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour))) {
            error("parse_pt_1_seq_id, not correct IP_ID_BEHAVIOUR\n");
            return false;
        }
        
        if ((end - pos) < 3) {
            error("parse_pt_1_seq_id, not enough data\n");
            return false;
        }
            
        uint8_t disc_crc_msbMsn = *pos++;
        uint8_t lsbMsn_ipId = *pos++;
        
        // clear crc
        *(pos - 2) &= 0xe3;
        uint8_t calcC3 = CRC3(pos-2, pos);
        *(pos - 2) = disc_crc_msbMsn;
        
        uint8_t read_crc3 = (disc_crc_msbMsn >> 2) & 7;
        if (calcC3 != read_crc3) {
            error("parse_pt_1_seq_id, checksum\n");
            SendNack();
            return false;
        }
        
        uint8_t lsbMsn = ((disc_crc_msbMsn & 3) << 4) | (lsbMsn_ipId >> 4);
        UpdateMSN(lsbMsn, 6, msn);
        UpdateIPIDOffset(lsbMsn_ipId & 0x0f, 4, ip_id_offset);
        UpdateIPIDFromOffset();

        return true;
    }
    
    /*
     pt_2_seq_id: This format can convey changes to the MSN and to the
     IP-ID. It is protected by a 7-bit CRC. It is similar in purpose
     to the UO-2-ID format in [RFC3095].
     
     
     // UOR-2-ID replacement
     COMPRESSED pt_2_seq_id {
     ENFORCE((ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_SEQUENTIAL) ||
     (ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
     discriminator =:= ’110’ [ 3 ];
     ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 6) [ 6 ];
     header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH) [ 7 ];
     msn =:= msn_lsb(8) [ 8 ];
     }     
     */
    bool
    DUDPProfile::parse_pt_2_seq_id(data_iterator& pos, const data_iterator& end)
    {
        if ((end - pos) < 3) {
            error("parse_pt_2_seq_id, not enough data\n");
            return false;
        }
		uint8_t disc_msb_ip_id_offset = *pos++;

		uint8_t new_ip_id_offset = (disc_msb_ip_id_offset & 0x1f) << 1;
		uint8_t lsb_ip_id_offset_crc7 = *pos;
		new_ip_id_offset |= (lsb_ip_id_offset_crc7 >> 7);
		*pos &= 0x80; // reset crc

		// advance pas crc
		++pos;

		uint8_t newmsn = *pos++;

		uint8_t calcCrc7 = CRC7(pos - 3, pos);

		if (calcCrc7 != (lsb_ip_id_offset_crc7 & 0x7f)) {
            error("parse_pt_2_seq_id, checksum\n");
			SendNack();
			return false;
		}

		UpdateMSN(newmsn, 8, msn);
		UpdateIPIDOffset(new_ip_id_offset, 6, ip_id_offset);
		UpdateIPIDFromOffset();
        return true;
    }

	bool
	DUDPProfile::parse_profile_2_3_4_flags_enc(data_iterator& pos, const data_iterator& end, bool& df, IPIDBehaviour_t& new_ip_id_behaviour) const
	{
        if ((end - pos) < 1) {
            error("parse_profile_2_3_4_flags_enc, not enough data\n");
            return false;
        }
		uint8_t val = *pos++;

		df = (val & 0x40) > 0;

		new_ip_id_behaviour = static_cast<IPIDBehaviour_t>((val & 0x30) >> 4);

		return true;
	}

} // ns ROHC
