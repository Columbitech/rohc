#include <rohc/rohc.h>
#include <rohc/decomp.h>
#include "duncomp_profile.h"

namespace ROHC
{
    DUncompressedProfile::DUncompressedProfile(Decompressor* decomp, unsigned int cid)
    : DProfile(decomp, cid)
    {
        
    }
    
    void
    DUncompressedProfile::MergeGlobalControlAndAppendHeaders(const ROHC::global_control&, data_t&)
    {
        ++numberOfPacketsReceived;
        state = FULL_CONTEXT;
    }
    
    void
    DUncompressedProfile::ParseCO(uint8_t packetTypeIndication, data_t &data, data_iterator pos, data_t &output)
    {
        if (FULL_CONTEXT != state)
        {
            return;
        }
        // pti is first byte of IP
        output.push_back(packetTypeIndication);
        // data contains the rest
        output.insert(output.end(), pos, data.end());
        ++numberOfPacketsReceived;
        dataSizeCompressed += distance(pos, data.end()) + 1;
        dataSizeUncompressed += distance(pos, data.end()) + 1;
    }
    
} // ns ROHC