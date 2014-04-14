#include "dprofile.h"
#include "dudp_profile.h"
#include "drtp_profile.h"
#include "duncomp_profile.h"
#include "network.h"
#include <cstdlib>
#include <rohc/decomp.h>
#include <rohc/compressor.h>

#include <cstring>

using namespace std;

namespace ROHC
{
    DProfile::DProfile(Decompressor* decomp, uint16_t cid)
    : decomp(decomp)
    ,cid(cid)
    ,state(NO_CONTEXT)
    ,msn(0)
    ,ip_id_offset(0)
    ,ip_id_behaviour(IP_ID_BEHAVIOUR_RANDOM)
    ,numberofIRPackets(0)
    ,numberOfPacketsReceived(0)
    ,dataSizeUncompressed(0)
    ,dataSizeCompressed(0)
    ,largeCID(decomp->LargeCID())
    ,ip()
    , packetsSinceLastAck(0)
    {
        memset(&ip, 0, sizeof(ip));
        ip.version = 4;
        ip.ihl = 5;
		SetReorderRatio(REORDERING_NONE);
    }
    
    DProfile*
    DProfile::Create(Decompressor* decomp,  uint16_t cid, unsigned int lsbProfileID)
    {
        if ((DUDPProfile::ProfileID() & 0xff) == lsbProfileID)
        {
            return new DUDPProfile(decomp, cid);
        }
        else if ((DRTPProfile::ProfileID() & 0xff) == lsbProfileID)
        {
            return new DRTPProfile(decomp, cid);
        }
        return new DUncompressedProfile(decomp, cid);
    }
    
    void
    DProfile::SendFeedback1() {
        if (5 == ++packetsSinceLastAck) {
            decomp->SendFeedback1(cid, static_cast<uint8_t>(msn));
            packetsSinceLastAck = 0;
        }
    }

	void DProfile::SendNack() {
		state = REPAIR_CONTEXT;
		decomp->SendNACK(cid, msn);
	}

    bool
    DProfile::parse_ipv4_static(ROHC::global_control &gc, const_data_iterator& pos, const_data_iterator& end) {
        if ((end - pos) < 10) {
            error("parse_ipv4_static, not enough data\n");
            return false;
        }
        gc.ip.version = 4;
        gc.ip.ihl = 5;
        
        uint8_t version_flagInnermost_ipReserved = *pos++;
        if (version_flagInnermost_ipReserved != 0x40) {
            error("parse_ipv4_static, not a valid ip version\n");
            return false;
        }
        
        gc.ip.protocol = *pos++;
        if (!GetValue(pos, end, gc.ip.saddr)) {
            error("parse_ipv4_static, could not get source address\n");
            return false;
        }
        
        if(!GetValue(pos, end, gc.ip.daddr)) {
            error("parse_ipv4_static, could not get source address\n");
            return false;
        }
        return true;
    }
    
    bool
    DProfile::parse_ipv4_regular_innermost_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator& end)
    {
        if ((end - pos) < 3) {
            error("parse_ipv4_regular_innermost_dynamic, not enough data\n");
            return false;
        }
        uint8_t reserved_Df_IpIdBehav = *pos++;
        
        if (reserved_Df_IpIdBehav & 4)
        {
            SetDontFragment(&gc.ip);
        }
        else
        {
            ClearDontFragment(&gc.ip);
        }
        
        gc.ip_id_behaviour = static_cast<IPIDBehaviour_t>(reserved_Df_IpIdBehav & 3);
        
        gc.ip.tos = *pos++;
        gc.ip.ttl = *pos++;
        
        return parse_ip_id_enc_dyn(gc, pos, end);
    }
    
    bool
    DProfile::parse_ip_id_enc_dyn(global_control& gc, const_data_iterator& pos, const_data_iterator& end)
    {
        if (IP_ID_BEHAVIOUR_ZERO == gc.ip_id_behaviour)
        {
            gc.ip.id = 0;
            return true;
        }
        else if (IP_ID_BEHAVIOUR_RANDOM == gc.ip_id_behaviour)
        {
            return GetValue(pos, end, gc.ip.id);
        }
        else if (IP_ID_BEHAVIOUR_SEQUENTIAL == gc.ip_id_behaviour)
        {
            return GetValue(pos, end, gc.ip.id);
        }
        else //IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED
        {
            return GetValue(pos, end, gc.ip.id);
        }
    }
    
    bool
    DProfile::parse_ip_id_sequential_variable(bool indicator, data_iterator& pos, const data_iterator& end, uint16_t& new_ip_id_offset, uint16_t& new_ip_id)
    {
        if (ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED)
        {
            if (indicator)
            {
                return GetValue(pos, end, new_ip_id);
            }
            else
            {
                if (std::distance(pos, end) < 1) {
                    error("parse_ip_id_sequential_variable not enough data");
                    return false;
                }
                UpdateIPIDOffset(*pos++, 8, new_ip_id_offset);
            }
        }
        return true;
    }

	void
	DProfile::UpdateIPIDFromOffset()
	{
        if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour)
        {
			ip.id = rohc_htons(msn + ip_id_offset);
        }
		else if (IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
        {
            ip.id = msn + ip_id_offset;
        }
	}

	void
	DProfile::UpdateIPIDOffsetFromID()
	{
		if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour)
		{
			ip_id_offset = rohc_htons(ip.id) - msn;
		}
		else if (IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
		{
			ip_id_offset = ip.id - msn;
		}
	}
    
    void
    DProfile::SetReorderRatio(ROHC::Reordering_t new_rr)
    {
		if (new_rr != reorder_ratio)
		{
			reorder_ratio = new_rr;
		}
    }
    
    uint16_t
    DProfile::UpdateMSN(uint16_t lsbMSN, unsigned int lsbMSNWidth, uint16_t& newMsn) const
    {
		// Store old val if newMsn is a reference to msn
		uint16_t oldMsn = msn;
		int lowerBound = msn - LSBWindowPForReordering(reorder_ratio, lsbMSNWidth);//msn - msn_p;
        uint16_t mask = (1<<lsbMSNWidth) - 1;

        newMsn = (msn & ~mask) | (lsbMSN & mask);

        if (newMsn < lowerBound)
        {
            newMsn += (1<<lsbMSNWidth);
        }
		uint16_t delta_msn = newMsn - oldMsn;

        return delta_msn;
    }
    
    void
    DProfile::UpdateIPIDOffset(uint8_t lsbIPID, unsigned int width, uint16_t& new_ip_id_offset) const
    {
        int lowerBound = ip_id_offset - 0;
        
        uint16_t mask = (1<<width) - 1;
        
        new_ip_id_offset = (ip_id_offset & ~mask) | (lsbIPID & mask);
        if (new_ip_id_offset < lowerBound)
        {
            new_ip_id_offset += (1<<width);
        }
    }
    
    void
    DProfile::parse_inferred_sequential_ip_id(uint16_t delta_msn)
    {
        if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour)
        {
            ip.id = rohc_htons(rohc_htons(ip.id) + delta_msn);
        }
        else if (IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
        {
            ip.id += delta_msn;
        }
    }

	bool
	DProfile::parse_ipv4_innermost_irregular(data_iterator& pos, const data_iterator& end)
	{
        // ipv4_irreg
        if (IP_ID_BEHAVIOUR_RANDOM == ip_id_behaviour)
        {
            return GetValue(pos, end, ip.id);
        }
		else if (IP_ID_BEHAVIOUR_ZERO == ip_id_behaviour)
		{
			ip.id = 0;
		}
		return true;
	}
    
} // namespace ROHC
