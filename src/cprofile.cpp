#include "cprofile.h"
#include "cudp_profile.h"
#include "crtp_profile.h"
#include "cuncomp_profile.h"
#include "ctcp_profile.h"
#include "network.h"
#include <cstdlib>
#include <cstring>
#include <rohc/decomp.h>
#include <rohc/compressor.h>

using namespace std;

namespace ROHC
{
    /**************************************************************************
     * Compression Profile
     **************************************************************************/
    CProfile::CProfile(Compressor* comp, uint16_t cid, const iphdr* ip)
    : compressor(comp),
    cid(cid),
    lastUsed(0),
    numberOfPacketsSent(0),
    numberOfIRPacketsSent(0),
    numberOfFOPacketsSent(0),
    numberOfSOPacketsSent(0),
    dataSizeUncompressed(0),
    dataSizeCompressed(0),
    numberOfIRPacketsSinceReset(0),
    numberOfFOPacketsSinceReset(0),
    msn(static_cast<uint16_t>(rand())),
    msnWindow(16, 16, 1)
    ,reorder_ratio(compressor->ReorderRatio())
    ,ip_id_behaviour(compressor->IPIdBehaviour())
    ,largeCID(compressor->LargeCID())
    ,state(IR_State)
    ,saddr(ip->saddr)
    ,daddr(ip->daddr)
    ,ip_id_offset(0)
    ,ip_id_offset_window(8, 16, 0) //(1<<16)/4 - 1)  // p = ((2^k) / 4) - 1)
    {
        //msn = 0;
        msnWindow.setP(LSBWindowPForReordering(reorder_ratio, 16));
        if (ip) {
            memcpy(&last_ip, ip, sizeof(last_ip));
        }
		memset(packetCount, 0, sizeof(packetCount));
    }
    
    unsigned int
    CProfile::ProfileIDForProtocol(const iphdr* ip, size_t totalSize, const std::vector<RTPDestination>& rtpDestinations) {
        if (CUDPProfile::ProtocolID() == ip->protocol)
        {
            const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
			if (totalSize >= (sizeof(iphdr) + sizeof(udphdr) + sizeof(rtphdr))) {
				const rtphdr* rtp = reinterpret_cast<const rtphdr*>(udp+1);
				// Make sure we have rtp version 2
				if (2 == rtp->version) {
					for (std::vector<RTPDestination>::const_iterator rd = rtpDestinations.begin();
						 rtpDestinations.end() != rd;
						 ++rd) {
						if (/*ip->daddr == rd->daddr &&*/
							udp->dest == rd->dport) {
							return CRTPProfile::ProfileID();
						}
					}
				}
			}
            return CUDPProfile::ProfileID();
        } 
        /*else if (CTCPProfile::ProtocolID() == ip->protocol) {
            return CTCPProfile::ProfileID();
        }*/
        
        return CUncompressedProfile::ProfileID();
    }
    
    CProfile* 
    CProfile::Create(Compressor* comp, uint16_t cid, unsigned int profileID, const iphdr* ip)
    {
        if (profileID == CUDPProfile::ProfileID())
        {
            return new CUDPProfile(comp, cid, ip);
        }
        else if (profileID == CRTPProfile::ProfileID())
        {
            return new CRTPProfile(comp, cid, ip);
        } else if (CTCPProfile::ProfileID() == profileID) {
            return new CTCPProfile(comp, cid, ip);
        }
        // TODO: other profiles
        return new CUncompressedProfile(comp, cid, ip);
    }

	uint16_t
    CProfile::UpdateMSN(uint16_t lsbMSN, unsigned int lsbMSNWidth, uint16_t& newMsn) const
    {
		uint16_t msn_p = static_cast<uint16_t>(LSBWindowPForReordering(reorder_ratio, lsbMSNWidth));
		// Store old val if newMsn is a reference to msn
		uint16_t oldMsn = msn;
        uint16_t lowerBound = static_cast<uint16_t>(msn - msn_p);
        
        uint16_t mask = static_cast<uint16_t>((1<<lsbMSNWidth) - 1);

        newMsn = static_cast<uint16_t>((msn & ~mask) | (lsbMSN & mask));
        if (newMsn < lowerBound)
        {
            newMsn += static_cast<uint16_t>(1<<lsbMSNWidth);
        }
	uint16_t delta_msn = static_cast<uint16_t>(newMsn - oldMsn);

        return delta_msn;
    }

    void
    CProfile::AckLsbMsn(uint8_t lsbMsn)
    {
        uint16_t ackMsn = 0;
		UpdateMSN(lsbMsn, 8, ackMsn);
        msnWindow.ackMSN(ackMsn);
        ip_id_offset_window.ackMSN(ackMsn);
		MsnWasAcked(ackMsn);
    }
    
    void
    CProfile::AckFBMsn(uint16_t fbMsn)
    {
        uint16_t ackMsn = 0;
		UpdateMSN(fbMsn, 14, ackMsn);
        msnWindow.ackMSN(ackMsn);
        ip_id_offset_window.ackMSN(ackMsn);
		MsnWasAcked(ackMsn);
    }
    
    void
    CProfile::increaseMsn()
    {
        // add the current msn
        msnWindow.add(msn, msn);
        ++msn;
    }
    
    void
    CProfile::UpdateIpIdOffset(const ROHC::iphdr *ip)
    {
        last_ip_id_offset = ip_id_offset;

        // TODO, handle big endian
        if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour)
        {
            uint16_t id = rohc_htons(ip->id);
            ip_id_offset = static_cast<uint16_t>(id - msn);
        }
        else if (IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
        {
            ip_id_offset = static_cast<uint16_t>(ip->id - msn);
        }
    }
    
    void
    CProfile::UpdateIpInformation(const ROHC::iphdr *ip)
    {
      	memcpy(&last_ip, ip, sizeof(last_ip));
		ip_id_offset_window.add(msn, ip_id_offset);
    }
    
    /*
     COMPRESSED ipv4_static {
     version_flag   =:= ’0’             [ 1 ];
     innermost_ip   =:= irregular(1)    [ 1 ];
     reserved       =:= ’000000’        [ 6 ];
     protocol       =:= irregular(8)    [ 8 ];
     src_addr       =:= irregular(32)   [ 32 ];
     dst_addr       =:= irregular(32)   [ 32 ];
     }
     */
    void 
    CProfile::create_ipv4_static(const iphdr* ip, data_t &output)
    {
        // Add ipv4_static
        output.push_back(0x40); // version_flag = '0', innermost_ip=1, reserved = '000000'
        output.push_back(ip->protocol);
        AppendData(output, ip->saddr);
        AppendData(output, ip->daddr);
    }
    
    /*
     COMPRESSED ipv4_regular_innermost_dynamic {
     ENFORCE((is_innermost == 1) && (profile_value != PROFILE_IP_0104));
     ENFORCE(ip_id_behavior_innermost.UVALUE == ip_id_behavior_value);
     reserved                   =:= ’00000’                                         [ 5 ];
     df                         =:= irregular(1)                                    [ 1 ];
     ip_id_behavior_innermost   =:= irregular(2)                                    [ 2 ];
     tos_tc                     =:= irregular(8)                                    [ 8 ];
     ttl_hopl                   =:= irregular(8)                                    [ 8 ];
     ip_id                      =:= ip_id_enc_dyn(ip_id_behavior_innermost.UVALUE)  [ 0, 16 ];
     }
     */    
    void
    CProfile::create_ipv4_regular_innermost_dynamic(const iphdr* ip, data_t &output)
    {
        uint8_t reservedDfIpIdBehaviour = 0;
        if (HasDontFragment(ip))
            reservedDfIpIdBehaviour |= 4;
        reservedDfIpIdBehaviour |= static_cast<uint8_t>(ip_id_behaviour);
        
        output.push_back(reservedDfIpIdBehaviour);
        
        output.push_back(ip->tos);
        output.push_back(ip->ttl);
        
        ip_id_enc_dyn(ip, output);
    }

	/*
	ip_id_enc_dyn(behavior)
	{
		UNCOMPRESSED {
			ip_id [ 16 ];
		}

		COMPRESSED ip_id_seq {
			ENFORCE((behavior == IP_ID_BEHAVIOR_SEQUENTIAL) ||
					(behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
			ENFORCE(ip_id_offset.UVALUE == ip_id.UVALUE - msn.UVALUE);
			ip_id =:= irregular(16) [ 16 ];
		}

		COMPRESSED ip_id_random {
			ENFORCE(behavior == IP_ID_BEHAVIOR_RANDOM);
			ip_id =:= irregular(16) [ 16 ];
		}

		COMPRESSED ip_id_zero {
			ENFORCE(behavior == IP_ID_BEHAVIOR_ZERO);
			ip_id =:= uncompressed_value(16, 0) [ 0 ];
		}
	}
	*/
    void
    CProfile::ip_id_enc_dyn(const ROHC::iphdr *ip, data_t &output)
    {
        switch (ip_id_behaviour)
        {
            case IP_ID_BEHAVIOUR_RANDOM:
                AppendData(output, ip->id);
                break;
            case IP_ID_BEHAVIOUR_SEQUENTIAL:
            {
                AppendData(output, ip->id);
            }
                break;
            case IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED:
                // TODO, fix for big endian
            {
                AppendData(output, ip->id);
            }
                break;
            case IP_ID_BEHAVIOUR_ZERO:
                // If zero, don't add anything
                break;
        }
    }
    
    void
    CProfile::ip_id_enc_irreg(const ROHC::iphdr *ip, data_t &output)
    {
		if (IP_ID_BEHAVIOUR_RANDOM == ip_id_behaviour)
			AppendData(output, ip->id);
    }
    
    /*
     ip_id_sequential_variable(behavior, indicator)
     {
     UNCOMPRESSED {
     ip_id [ 16 ];
     }
     COMPRESSED short {
     ENFORCE((behavior == IP_ID_BEHAVIOR_SEQUENTIAL) ||
     (behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
     ENFORCE(indicator == 0);
     ip_id =:= ip_id_lsb(behavior, 8) [ 8 ];
     }
     COMPRESSED long {
     ENFORCE((behavior == IP_ID_BEHAVIOR_SEQUENTIAL) ||
     (behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
     ENFORCE(indicator == 1);
     ENFORCE(ip_id_offset.UVALUE == ip_id.UVALUE - msn.UVALUE);
     ip_id =:= irregular(16) [ 16 ];
     }
     COMPRESSED not_present {
     ENFORCE((behavior == IP_ID_BEHAVIOR_RANDOM) ||
     (behavior == IP_ID_BEHAVIOR_ZERO));
     }
     }
     */
    void
    CProfile::ip_id_sequential_variable(bool indicator, const iphdr* ip, data_t &output)
    {
        if (IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
            IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour)
        {
            // long
            if (indicator)
            {
                AppendData(output, ip->id);
            }
            // short
            else
            {
                output.push_back(static_cast<uint8_t>(ip_id_offset));
            }
        }
        // Else random or zero, don't add
    }

    void 
    CProfile::create_ipv4_innermost_irregular(const ROHC::iphdr *ip, data_t &output)
    {
        ip_id_enc_irreg(ip, output);
    }

	void 
	CProfile::IncreasePacketCount(PacketType packetType)
	{
		++packetCount[packetType];
		compressor->IncreasePacketCount(packetType);
	}

        
} // namespace ROHC
