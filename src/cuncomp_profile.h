#pragma once

#include "cprofile.h"

/*
 * See RFC 4995
 * 5.4
 */


namespace ROHC
{
    /**************************************************************************
     * Compression Profile
     **************************************************************************/
    
    class CUncompressedProfile : public CProfile
    {
    public:
        CUncompressedProfile(Compressor* comp, unsigned int cid, const iphdr* ip);
        
        virtual unsigned int ID() const {return ProfileID();}
        
        /*
         * always return true since this one can send any data
         */
        virtual bool Matches(unsigned int profileID, const iphdr*) const {return profileID == ID();}
        
        virtual void Compress(const data_t& data, data_t& output);
        
        // Statics
    public:
        static uint16_t ProfileID() {return 0x0000;}
    private:
		/**
		 * called by AckLsbMsn or AckFBMsn with the full MSN that was acked
		 */
		virtual void MsnWasAcked(uint16_t /*ackedMSN*/) {}

		/*
		 * 14 bit MSN
		 */
		virtual void NackMsn(uint16_t /*fbMSN*/) {};

		/*
		 * 14 bit MSN
		 */
		virtual void StaticNackMsn(uint16_t /*fbMSN*/) {};
        bool IRRequested;
        
    };
} // ns ROHC