#pragma once

#include <rohc/rohc.h>
#include "lsb.h"
#include "network.h"

#include <deque>

namespace ROHC
{

    /**************************************************************************
     * Compression Profile
     **************************************************************************/


    struct RTPDestination;
    class Compressor;
    class CProfile
    {
        void operator=(const CProfile&);
        CProfile(const CProfile&);
    public:
        CProfile (Compressor* comp, uint16_t cid, const iphdr* ip);
        virtual ~CProfile() {}
        
        // Virtual functions
    public:
        /**
         * return the profile ID
         */
        virtual unsigned int ID() const = 0;
        virtual bool Matches(unsigned int profileID, const iphdr* ip) const = 0;
        virtual void Compress(const data_t& data, data_t& output) = 0;
        
        
    public: // Public functions
        void SetLastUsed(time_t millis) {lastUsed = millis;}
        time_t LastUsed() const {return lastUsed;}
        
        uint16_t CID() const {return cid;}

		/*
		 * msn with 8 bits, (from feedback 1)
		 */
        void AckLsbMsn(uint8_t lsbMsn);
        
		/*
         * msn with 14 bits (from feedback 2)
		 */
        void AckFBMsn(uint16_t fbMsn);

		/*
		 * 14 bit MSN
		 */
		virtual void NackMsn(uint16_t fbMSN) = 0;

		/*
		 * 14 bit MSN
		 */
		virtual void StaticNackMsn(uint16_t fbMSN) = 0;

        
        // Static functions
    public:
        static unsigned int ProfileIDForProtocol(const iphdr*, size_t totalSize, const std::vector<RTPDestination>&);
        static CProfile* Create(Compressor* comp, uint16_t cid, unsigned int profileID, const iphdr* ip);  
        
    protected:
		/**
		 * called by AckLsbMsn or AckFBMsn with the full MSN that was acked
		 */
		virtual void MsnWasAcked(uint16_t ackedMSN) = 0;

		void create_ipv4_static(const iphdr* ip, data_t& output);
        void create_ipv4_regular_innermost_dynamic(const iphdr* ip, data_t& output);
        void create_ipv4_innermost_irregular(const iphdr* ip, data_t& output);
        void ip_id_enc_dyn(const iphdr* ip, data_t& output);
        void ip_id_enc_irreg(const iphdr* ip, data_t& output);
        void ip_id_sequential_variable(bool indicator, const iphdr* ip, data_t& output);

        // return number of bits for LSB encoding msn given the current window
        void increaseMsn();
        
        /*
         returns true if ip_id_offset has changed
         */
        void UpdateIpIdOffset(const iphdr* ip);
        void UpdateIpInformation(const iphdr* ip);
        uint16_t ip_id_lsb(unsigned int k);
        
		inline bool TOSChanged(const iphdr* ip) const { return ip->tos != last_ip.tos;}
        inline bool TTLChanged(const iphdr* ip) const { return ip->ttl != last_ip.ttl;}
        inline bool DFChanged(const iphdr* ip) const {return HasDontFragment(ip) != HasDontFragment(&last_ip);}
        inline bool IPIDOffsetChanged() const {return last_ip_id_offset != ip_id_offset;}
        

		void IncreasePacketCount(PacketType packetType);
    protected:
		unsigned int IpIdOffsetWidth() const
		{
			return ip_id_offset_window.width(ip_id_offset);
		}

		uint16_t IpIdOffset() const {return ip_id_offset;}

		uint16_t UpdateMSN(uint16_t lsbMSN, unsigned int lsbMSNWidth, uint16_t& newMsn) const;

        Compressor* compressor;
        uint16_t cid;

        time_t lastUsed;
        
        
        unsigned int numberOfPacketsSent;
        unsigned int numberOfIRPacketsSent;
        unsigned int numberOfFOPacketsSent;
        unsigned int numberOfSOPacketsSent;
        
        size_t dataSizeUncompressed;
        size_t dataSizeCompressed;

        unsigned int numberOfIRPacketsSinceReset;
        unsigned int numberOfFOPacketsSinceReset;
        
        /**
         * Global Control fields
         * RFC 5225, 6.8.2.4
         */
        
        // 6.3.1
        uint16_t msn;
        WLSB<int> msnWindow;
        // 6.3.2
        Reordering_t reorder_ratio; // coded as two bits, 
        // 6.3.3
        IPIDBehaviour_t ip_id_behaviour; // TODO, try to detect this
        
        bool largeCID;
        
        enum
        {
            IR_State,
            FO_State,
            SO_State
        } state;
        
        uint32_t saddr;
        uint32_t daddr;

		iphdr last_ip;
    private:
        uint16_t last_ip_id_offset;

		uint16_t ip_id_offset;
        WLSB<int> ip_id_offset_window;

		size_t packetCount[PT_2_SEQ_TS + 1];
    };
} // ns ROHC