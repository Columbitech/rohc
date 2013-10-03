#include "cuncomp_profile.h"
#include <rohc/compressor.h>
#include <iterator>

namespace ROHC
{
    /**************************************************************************
     * Compression Profile
     **************************************************************************/
    
    CUncompressedProfile::CUncompressedProfile(Compressor* comp, unsigned int cid, const iphdr* ip)
    : CProfile(comp, cid, ip)
    , IRRequested(true)
    {
        
    }
    
    void
    CUncompressedProfile::Compress(const data_t &data, data_t &output)
    {
        size_t outputStart = output.size();
        
        bool largeCID = compressor->LargeCID();
        
        if (!largeCID && cid > 0)
        {
            output.push_back(CreateShortCID(cid));
        }

        if (IRRequested)
        {
            output.push_back(CreateIR(0));
            
            if (largeCID)
            {
                SDVLEncode(back_inserter(output), cid);
            }
            
            uint8_t lsbProfile = CUncompressedProfile::ProfileID() & 0xff;
            
            output.push_back(lsbProfile);
            
            uint8_t crc = CRC8(output.begin() + outputStart, output.end());
            output.push_back(crc);
            
            output.insert(output.end(), data.begin(), data.end());
            IRRequested = false;
        }
        else
        {
            const_data_iterator pos = data.begin();
            output.push_back(*pos++);
            if (largeCID)
            {
                SDVLEncode(back_inserter(output), cid);
            }
            output.insert(output.end(), pos, data.end());
        }
    }

} // ns ROHC