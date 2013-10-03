#pragma once

#include "dprofile.h"

/*
 * See RFC 4995
 * 5.4
 */


namespace ROHC
{
    class DUncompressedProfile : public DProfile
    {
    public:
        
        DUncompressedProfile(Decompressor* decomp, unsigned int cid);
        
        uint8_t LSBID() const {return static_cast<uint8_t>(0x0000);};
        static uint16_t ProfileID() {return 0x0100;}

        static const_data_iterator ParseIR(global_control& /*gc*/, const data_t& /*data*/, const_data_iterator pos) {return pos;}
        void MergeGlobalControlAndAppendHeaders(const global_control& gc, data_t& output);
        
        void ParseCO(uint8_t packetTypeIndication, data_t& data, data_iterator pos, data_t& output);
        void ParseCORepair(const data_t& /*data*/, const_data_iterator /*r2_crc3_pos*/, data_t& /*output*/) {};
        size_t IRCRCSize(const_data_iterator ) {return 0;}        
    };
    
} // ns ROHC
