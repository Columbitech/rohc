#pragma once

#include "cprofile.h"

namespace ROHC {
    class CTCPProfile : public CProfile {
    private:
    public:
        CTCPProfile(Compressor* comp, uint16_t cid, const iphdr* ip);
        static uint16_t ProfileID() {return 0x0106;}
        static uint16_t ProtocolID() {return 6;}
        
        /**
         * return the profile ID
         */
        virtual unsigned int ID() const {return ProfileID();}
        virtual bool Matches(unsigned int profileID, const iphdr* ip) const;
        virtual void Compress(const data_t& data, data_t& output);

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

    private:
        void CreateIR(const iphdr* ip, const tcphdr* tcp, data_t& output);
        void CreateCO(const iphdr* ip, const tcphdr* tcp, data_t& output);
        
        void create_tcp_static(const tcphdr* tcp, data_t& output);
        void create_tcp_dynamic(const tcphdr* tcp, data_t& output);
        
        void AdvanceState(bool calledFromFeedback, bool ack);
        
        tcphdr last_tcp;
        
    };
} // ns ROHC
