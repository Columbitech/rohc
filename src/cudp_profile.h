#pragma once

/**
 * UDP/IP profile
 */

#include "cprofile.h"

namespace ROHC
{
    struct udphdr;
    /**************************************************************************
     * Compression Profile
     **************************************************************************/
    class CUDPProfile : public CProfile
    {
    public:
        CUDPProfile(Compressor* comp, uint16_t cid, const iphdr* ip);
        
        bool Matches(unsigned int profileID, const iphdr* ip) const;
        
        virtual unsigned int ID() const {return ProfileID();}
        
        virtual void Compress(const data_t& data, data_t& output);

    // Statics
    public:
        static uint16_t ProfileID() {return 0x0102;}
        static uint16_t ProtocolID() {return 17;}
        
        /**
         * used by the rtp profile
         */
        static void create_udp_static(uint16_t sport, uint16_t dport, data_t& output);
        static void create_udp_with_checksum_irregular(const udphdr* udp, data_t& output);
        
    protected:
		/**
		 * called by AckLsbMsn or AckFBMsn with the full MSN that was acked
		 */
		virtual void MsnWasAcked(uint16_t ackedMSN);
		/*
		 * 14 bit MSN
		 */
		virtual void NackMsn(uint16_t fbMSN);

		/*
		 * 14 bit MSN
		 */
		virtual void StaticNackMsn(uint16_t fbMSN);

        static void create_udp_endpoint_dynamic(uint16_t msn, Reordering_t reorder_ratio, const udphdr* udp, data_t& output);
        void CreateIR(const iphdr* ip, const udphdr* udp, data_t& output);
        void CreateCO(const iphdr* ip, const udphdr* udp, data_t& output);
        void create_co_common(const ROHC::iphdr *ip, data_t &output);
        void create_co_repair(const ROHC::iphdr *ip, const ROHC::udphdr *udp, data_t &output);
        void create_pt_0_crc3(data_t& output);
        void create_pt_0_crc7(data_t& output);
        void create_pt_1_seq_id(data_t& output);
        void create_pt_2_seq_id(data_t& output);
        
        uint8_t control_crc3() const;
        void profile_2_3_4_flags_enc(bool flag, const iphdr* ip, data_t& output);
        
        void AdvanceState(bool calledFromFeedback, bool ack);
    protected:
        uint16_t sport;
        uint16_t dport;
        bool checksum_used;
    };
    
} // ns ROHC