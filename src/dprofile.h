#pragma once

#include <rohc/rohc.h>
#include "network.h"
#include "lsb.h"

namespace ROHC
{    
    struct global_control
    {
        uint16_t    msn;
        Reordering_t reorder_ratio;
        // ip_id fields are for innermost IP header only
        //uint16_t    ip_id_offset;
        IPIDBehaviour_t ip_id_behaviour;
        
        // Used by RTP
        uint32_t    ts_stride;
        uint32_t    time_stride;
        uint32_t    ts_scaled;
        uint32_t    ts_offset;
        
        iphdr       ip;
        
        bool        udp_checksum_used;
        udphdr      udp;
        
        rtphdr      rtp;
    };
    
    class Decompressor;
    class DProfile
    {
        void operator=(const DProfile&);
        DProfile(const DProfile&);
    public:
        DProfile (Decompressor* decomp, uint16_t cid);
        virtual ~DProfile() {};
        
        // To be overridden
    public:
        /**
         * returns the LSB part of the profile ID
         */
        virtual uint8_t LSBID() const = 0;
        //        virtual void InitializeGlobalControl(global_control& gc);
        virtual void MergeGlobalControlAndAppendHeaders(const global_control& gc, data_t& output) = 0;
        virtual void ParseCO(uint8_t packetTypeIndication, data_t& data, data_iterator pos, data_t& output) = 0;
        virtual void ParseCORepair(const data_t& data, const_data_iterator r2_crc3_pos, data_t& output) = 0;
        
        // Static functions
    public:
        static DProfile* Create(Decompressor* decomp, uint16_t cid, unsigned int lsbProfileID);
    protected:
        static bool parse_ipv4_static(global_control& gc, const_data_iterator& pos, const_data_iterator& end);
        static bool parse_ipv4_regular_innermost_dynamic(global_control& gc, const_data_iterator& pos, const_data_iterator& end);
        static bool parse_ip_id_enc_dyn(global_control& gc, const_data_iterator& pos, const_data_iterator& end);

        bool parse_ip_id_sequential_variable(bool indicator, data_iterator& pos, const data_iterator& end, uint16_t& new_ip_id_offset, uint16_t& new_ip_id);
        void parse_inferred_sequential_ip_id(uint16_t delta_msn);
        uint16_t UpdateMSN(uint16_t lsbMSN, unsigned int lsbMSNWidth, uint16_t& newMsn) const;
        void UpdateIPIDOffset(uint8_t lsbIPID, unsigned int width, uint16_t& new_ip_id_offset) const;
		void UpdateIPIDFromOffset();
		void UpdateIPIDOffsetFromID();
    protected:
        void SendFeedback1();
		void SendNack();
        
        void SetReorderRatio(Reordering_t new_rr);
        Reordering_t GetReorderRatio() const {return reorder_ratio;}
        bool parse_ipv4_innermost_irregular(data_iterator& pos, const data_iterator& end);
    protected:
        Decompressor* decomp;
        uint16_t cid;
        
        enum
        {
            NO_CONTEXT,
            REPAIR_CONTEXT,
            FULL_CONTEXT        
        } state;
        
        /**
         * Global Control fields
         * RFC 5225, 6.8.2.4
         */
        
        // 6.3.1
        uint16_t msn;

        // 6.3.2
        uint16_t ip_id_offset;
        // 6.3.3
        IPIDBehaviour_t ip_id_behaviour; 
        
        unsigned int numberofIRPackets;
        
        unsigned int numberOfPacketsReceived;
        size_t dataSizeUncompressed;
        size_t dataSizeCompressed;  
        bool largeCID;
        
        // Stored ip header
        iphdr ip;
        
        size_t packetsSinceLastAck;
    private:
        Reordering_t reorder_ratio; // coded as two bits
    };
} // ns ROHC
