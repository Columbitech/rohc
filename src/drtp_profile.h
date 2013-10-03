#pragma once

#include "dprofile.h"

namespace ROHC
{
    class DRTPProfile : public DProfile
    {
        void operator=(const DRTPProfile&);
        DRTPProfile(const DRTPProfile&);
        DRTPProfile();
    public:
        DRTPProfile(Decompressor* decomp, uint16_t cid);
        virtual uint8_t LSBID() const { return static_cast<uint8_t>(ProfileID());}
        static uint16_t ProfileID() {return 0x0101;}

        void MergeGlobalControlAndAppendHeaders(const global_control& gc, data_t& output);
        static bool ParseIR(global_control& gc, const data_t& data, const_data_iterator& pos);
        virtual void ParseCO(uint8_t packetTypeIndication, data_t& data, data_iterator pos, data_t& output);
        
        
        virtual void ParseCORepair(const data_t& data, const_data_iterator r2_crc3_pos, data_t& output);

        
        
    protected:
        static bool parse_rtp_static(global_control& gc, const_data_iterator& pos, const_data_iterator end);
        static bool parse_rtp_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator end);
        static bool parse_udp_regular_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator end);

        bool parse_co_common(data_iterator& pos, const data_iterator& end);
		bool parse_pt_0_crc3(data_iterator& pos, const data_iterator& end);
		bool parse_pt_0_crc7(data_iterator& pos, const data_iterator& end);
		bool parse_pt_1_rnd(data_iterator& pos, const data_iterator& end);
		bool parse_pt_1_seq_id(data_iterator& pos, const data_iterator& end);
		bool parse_pt_1_seq_ts(data_iterator& pos, const data_iterator& end);
		bool parse_pt_2_rnd(data_iterator& pos, const data_iterator& end);
		bool parse_pt_2_seq_id(data_iterator& pos, const data_iterator& end);
		bool parse_pt_2_seq_both(data_iterator& pos, const data_iterator& end);
		bool parse_pt_2_seq_ts(data_iterator& pos, const data_iterator& end);

		bool parse_profile_1_7_flags1_enc(bool flags1_indicator, data_iterator& pos, const data_iterator& end, bool& ttl_hopl_indicator, bool& tos_tc_indicator, bool& df, IPIDBehaviour_t& new_ip_id_behaviour, Reordering_t& new_reorder_ratio) const;
		
        bool parse_profile_1_flags2_enc(bool flags2_indicator, data_iterator& pos, const data_iterator& end, bool& list_indicator, bool& pt_indicator, bool& tis_indicator, bool& pad_bit, bool& extension) const;
        
        bool parse_sdvl_sn_lsb(data_iterator& pos, const data_iterator& end, uint16_t& new_msn, unsigned int& delta_msn) const;
		
        bool parse_variable_unscaled_timestamp(bool tss_indicator, bool tsc_indicator, data_iterator& pos, const data_iterator& end, uint32_t& new_timestamp) const;

		uint8_t control_crc3(Reordering_t newRR, uint32_t new_ts_stride, uint32_t new_time_stride) const;

		bool parse_inferred_scaled_ts(uint16_t delta_msn);

		void UpdateTimestamp(uint32_t ts_scaled_lsb, unsigned int width);

        uint32_t ts_stride;
        uint32_t time_stride;

		uint32_t ts_scaled;
		uint32_t ts_offset;
        
        bool udp_checksum_used;
        udphdr udp;
        rtphdr rtp;
    };
} // ns ROHC