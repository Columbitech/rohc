#pragma once

/**
 * UDP/IP profile
 */

#include "dprofile.h"

namespace ROHC
{
    class DUDPProfile : public DProfile
    {
    public:
        DUDPProfile(Decompressor* decomp, uint16_t cid);
        
        virtual uint8_t LSBID() const { return static_cast<uint8_t>(ProfileID());}
        static uint16_t ProfileID() {return 0x0102;}
        
        static bool ParseIR(global_control& gc, const data_t& data, const_data_iterator& pos);
        virtual void ParseCO(uint8_t packetTypeIndication, data_t& data, data_iterator pos, data_t& output);
        virtual void ParseCORepair(const data_t& data, const_data_iterator r2_crc3_pos, data_t& output);
        
        void MergeGlobalControlAndAppendHeaders(const global_control& gc, data_t& output);        
        
        
        static bool parse_udp_static(global_control& gc, const_data_iterator& pos, const_data_iterator& end);
        
    private:
        void InitIPHeader(iphdr* ip);
        static bool parse_udp_endpoint_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator& end);
        
        bool parse_co_common(data_iterator& pos, const data_iterator& end);
        bool parse_pt_0_crc3(data_iterator& pos, const data_iterator& end);
        bool parse_pt_0_crc7(data_iterator& pos, const data_iterator& end);
        bool parse_pt_1_seq_id(data_iterator& pos, const data_iterator& end);
        bool parse_pt_2_seq_id(data_iterator& pos, const data_iterator& end);

		bool parse_profile_2_3_4_flags_enc(data_iterator& pos, const data_iterator& end, bool& df, IPIDBehaviour_t& new_ip_id_behaviour) const;

        uint8_t control_crc3(Reordering_t newRR, uint16_t new_msn, IPIDBehaviour_t new_ip_id_behaviour) const;
        
        bool checksum_used;
        udphdr udp;
        
    };
} // ns ROHC