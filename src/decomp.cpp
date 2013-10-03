#include <rohc/decomp.h>
#include <rohc/compressor.h>
#include <rohc/rohc.h>
#include <rohc/log.h>
#include "dprofile.h"
#include "dudp_profile.h"
#include "duncomp_profile.h"
#include "drtp_profile.h"

#include <iterator>
#include <cstring>

using namespace std;

namespace ROHC 
{
    Decompressor::Decompressor(bool largeCID, Compressor* compressor)
    : compressor(compressor),
    largeCID(largeCID),
    contexts(),
    numberOfPacketsReceived(0),
    dataSizeUncompressed(0),
    dataSizeCompressed(0)
    {
    }
    
    Decompressor::~Decompressor() {
        for (context_t::iterator i = contexts.begin(); contexts.end() != i; ++i) {
            delete i->second;
        }
    }
    
    void
    Decompressor::Decompress(const uint8_t* data, size_t dataSize, data_t& output) {
        data_t d(data, data + dataSize);
        Decompress(d, output);
    }
    
    void
    Decompressor::Decompress(data_t& data, data_t& output)
    {
        output.reserve(data.size());
        data_iterator pos = data.begin();
        size_t outputInitialSize = output.size();
        
		while ((data.end() != pos) &&
			IsPadding(*pos)) ++pos;
        
		while ((data.end() != pos) &&
			IsFeedback(*pos))
        {
            // If feedback parsing failes, we will not continue since we don't know what kind of data we get
            if (!ParseFeedback(data, pos)) {
                error("Decompressor, failed to parse feedback\n");
                return;
            }
        }

		if (data.end() == pos) {
            //info("Decompressor::Decompress, no data left\n");
			return;
        }
        
        data_iterator headerStart = pos;
        
        uint8_t packetTypeIndication = 0;
        if (!largeCID && IsAddCID(*pos))
        {
            packetTypeIndication = *(pos+1);
        }        
        else
        {
            packetTypeIndication = *pos;
        }
        
        if (IsIR(packetTypeIndication))
        {
            ParseIR(data, headerStart, output);
        }
        else if (IsIR_DYN(packetTypeIndication))
        {
            // ParseIRDYN
        }
        else if (IsCORepairPacket(packetTypeIndication))
        {
            ParseCORepair(data, headerStart, output);
        }
        else
        {
            ParseCO(data, headerStart, output);
        }
        
        ++numberOfPacketsReceived;
        dataSizeCompressed += data.end() - headerStart;
        dataSizeUncompressed += output.size() - outputInitialSize;
    }

    /*
     * See RFC 4995 5.2.4.1
       0   1   2   3   4   5   6   7
     +---+---+---+---+---+---+---+---+
     | 1   1   1   1   0 | Code      | feedback type
     +---+---+---+---+---+---+---+---+
     : Size                          : if Code = 0
     +---+---+---+---+---+---+---+---+
     : Add-CID octet                 : if for small CIDs and (CID != 0)
     +---+---+---+---+---+---+---+---+
     :                               :
     / large CID (5.3.2 encoding)    / 1-2 octets if for large CIDs
     :                               :
     +---+---+---+---+---+---+---+---+
     / FEEDBACK data                 / variable length
     +---+---+---+---+---+---+---+---+
     Code: 0 indicates that a Size octet is present.
     1-7 indicates the size of the feedback data field, in octets.
     Size: Indicates the size of the feedback data field, in octets. 
     */
    
    
    bool 
    Decompressor::ParseFeedback(data_t& data, data_iterator& pos)
    {
        uint8_t feedbackCode = UnmaskFeedback(*pos++);
        size_t feedbackSize = feedbackCode;

		//cout << "feedback code: " << (unsigned) feedbackCode << endl;
        if (!feedbackSize)
        {
            feedbackSize = *(pos++);
        }

		if (!feedbackSize) {
			error("Should have received feedback size, but got none\n");
            return false;
		}
        
		data_iterator crcStart = pos;
        uint32_t cid = 0;
        if (!largeCID && IsAddCID(*pos))
        {
            cid = UnmaskShortCID(*pos++);
        }
        else if (largeCID)
        {
            if (!SDVLDecode(pos, data.end(), &cid))
                return false;
        }

		//cout << "Feedback cid: " << (unsigned) cid << endl;
        
        if (1 == feedbackSize)
        {
            compressor->ReceivedFeedback1(cid, *pos++);
        }
        else
        {
            data_iterator fbData = pos;
            
            uint8_t actypeMsn = *pos++;
            uint8_t lsbMsn = *pos++;
            
            // verify crc
            data_iterator crcPos = pos++;
            uint8_t receviedCRC = *crcPos;
            *crcPos = 0;
            uint8_t calcCRC = CRC8(crcStart, fbData + feedbackSize);
            *crcPos = receviedCRC;
            
            if (calcCRC == receviedCRC)
            {
                uint16_t msn = ((actypeMsn & 0x3f) << 8) + lsbMsn;
                FBAckType_t type = static_cast<FBAckType_t>(actypeMsn & 0xc0);
                compressor->ReceivedFeedback2(cid, msn, type, pos, fbData + feedbackSize);
            }
			else {
                error("Feedback CRC failed");
                return false;
			}
            pos = fbData + feedbackSize;
        }
        
        return true;
    }
    
    void
    Decompressor::ParseIR(data_t& data, data_iterator irDataStart, data_t& output)
    {
        data_iterator pos = irDataStart;
        
        uint32_t cid = 0;
        if (!largeCID && IsAddCID(*pos))
        {
            cid = UnmaskShortCID(*pos++);
        }
        
        uint8_t packetTypeIndication = *pos++;
        
        if (largeCID)
        {
            if (!SDVLDecode(pos, data.end(), &cid)){
                return;
            }
        }
        
        uint8_t lsbProfile = *pos++;
        
        // Store CRC position
        
        data_iterator crcPos = pos++;  
        
        global_control gc;
        memset(&gc, 0, sizeof(gc));
        
        const_data_iterator endOfIr = pos;
        if (lsbProfile == (DUDPProfile::ProfileID() & 0xff))
        {
            if (packetTypeIndication != 0xfd) {
                error("Decompressor::Decompress, wrong pti\n");
				SendStaticNACK(cid);
                return;
			}
            
            if(!DUDPProfile::ParseIR(gc, data, endOfIr)) {
                error("Decompressor, failed to parse UDP IR\n");
                return;
            }
        }
        else if (lsbProfile == (DUncompressedProfile::ProfileID() & 0xff))
        {
            if (packetTypeIndication != 0xfc) {
                error("Decompressor::Decompress, wrong pti\n");
				SendStaticNACK(cid);
                return;
			}

            endOfIr = DUncompressedProfile::ParseIR(gc, data, pos);
            // endOfIr points past CRC and CRC should not be included
            // when calculating CRC for uncompressed;
            --endOfIr;
        }
        else if (lsbProfile == (DRTPProfile::ProfileID() & 0xff))
        {
            if (packetTypeIndication != 0xfd)
            {
                error("Decompressor::Decompress, wrong pti\n");
				SendStaticNACK(cid);
                return;
            }
            if (!DRTPProfile::ParseIR(gc, data, endOfIr)) {
                error("Decompressor, failed to parse RTP IR\n");
                return;
            }
        }
        else
        {
            error("Decompressor::ParseIR, unknown profile: %u\n", (unsigned)lsbProfile);
//            PrintData(data.begin(), data.begin() + 40);
            SendStaticNACK(cid);
            return;
        }
        
#if 0
        // FRJA, not sure why this check was here
        if (data.end() == endOfIr) {
            error("ParseIR failed\n");
            SendStaticNACK(cid);
            return;
        }
#endif
        
        uint8_t readCRC = *crcPos;
        
        *crcPos = 0;
        
        uint8_t calcCRC = CRC8(irDataStart, endOfIr);
        
        *crcPos = readCRC;
        
        if (calcCRC != readCRC)
        {
            error("Decompressor::ParseIR, CRC8 failure\n");
            
            // TODO, check if we have this profile and have that 
            // send a nack
            SendStaticNACK(cid);
            return;
            
        }

        if (lsbProfile == (DUncompressedProfile::ProfileID() & 0xff))
        {
            // Move back to packet data
            ++endOfIr;
        }
        

        context_t::iterator existingProfile = contexts.find(cid);
        
        DProfile* profile = 0;
        
        if (contexts.end() != existingProfile)
        {
            // TODO:
            // Is this correct, do we need to verify more than if the profile is the same
            // to use an existing context?
            if (existingProfile->second->LSBID() != lsbProfile)
            {
                delete existingProfile->second;
                existingProfile = contexts.end();
            }
            else
            {
                profile = existingProfile->second;
            }
        }
        
        if (!profile)
        {
            profile = DProfile::Create(this, cid, lsbProfile);
        }    
        
        // Store the profile if CS is ok
        contexts[cid] = profile;
        
        size_t outputInitSize = output.size();

        profile->MergeGlobalControlAndAppendHeaders(gc, output);
        
//        cout << "Decompressor:ParseIR header size: " << (endOfIr - irDataStart) << endl;
        
        output.insert(output.end(), endOfIr, const_data_iterator(data.end()));
        
        setLengthsAndIPChecksum(output.begin() + outputInitSize, output.end());
    }
    
    void 
    Decompressor::ParseCO(data_t& data, data_iterator pos, data_t& output)
    {
        uint32_t cid = 0;
        if (!largeCID && IsAddCID(*pos))
        {
            cid = UnmaskShortCID(*pos++);
        }
        
        uint8_t packetTypeIndication = *pos++;
        if (largeCID)
        {
            if (!SDVLDecode(pos, data.end(), &cid))
                return;
        }
        
        context_t::iterator i = contexts.find(cid);
        if (contexts.end() == i)
        {
            SendStaticNACK(cid);
            return;
        }
        
        DProfile* profile = i->second;
        profile->ParseCO(packetTypeIndication, data, pos, output);
    }
    
    
    /**
       0   1   2   3   4   5   6   7
      --- --- --- --- --- --- --- ---
     : Add-CID octet                 : if for small CIDs and CID 1-15
     +---+---+---+---+---+---+---+---+
     | 1   1   1   1   1   0   1   1 | discriminator
     +---+---+---+---+---+---+---+---+
     :                               :
     / 0, 1, or 2 octets of CID      / 1-2 octets if large CIDs
     :                               :
     +---+---+---+---+---+---+---+---+
     |r1 |           CRC-7           |
     +---+---+---+---+---+---+---+---+
     | r2                |   CRC-3   |
     +---+---+---+---+---+---+---+---+
     |                               |
     / Dynamic chain                 / variable length
     |                               |
      - - - - - - - - - - - - - - - -
     */
    
    void
    Decompressor::ParseCORepair(data_t &data, data_iterator pos, data_t &output)
    {
        uint32_t cid = 0;
        data_iterator headerStart = pos;
        
        if (!largeCID && IsAddCID(*pos))
        {
            cid = UnmaskShortCID(*pos++);
        }
        
        // skip discriminiator;
        ++pos;
        
        if (!largeCID)
        {
            if (!SDVLDecode(pos, data.end(), &cid)) {
                return;
            }
        }
        
        uint8_t r1_crc7 = *pos;
        if (r1_crc7 & 0x80)
        {
            // TODO Send nack?
            return;
        }
        
        *pos = 0;
        
        // TODO, this is not correct, since we may have packet data
        // at the end
        uint8_t calcCRC = CRC7(headerStart, data.end());
        
        // write back old crc
        *pos++ = r1_crc7;
        
        if (r1_crc7 != calcCRC)
        {
            // TODO: Send nack
            return;
        }
        
        context_t::iterator i = contexts.find(cid);
        if (contexts.end() == i)
        {
            return;
        }
        
        i->second->ParseCORepair(data, pos, output);
    }
    
    void
    Decompressor::SendNACK(unsigned int cid, uint16_t msn)
    {
		data_t options;
        SendFeedback2(cid, msn, FB_NACK, options);
    }

	void
    Decompressor::SendStaticNACK(unsigned int cid)
    {
		data_t options;

		// Add a ACKNUMBER-NOT-VALID, see RFC 5225, 6.9.2.2
		options.push_back(static_cast<uint8_t>(FBO_ACKNUMBER_NOT_VALID));

        SendFeedback2(cid, 0, FB_STATIC_NACK, options);
    }

    void
    Decompressor::SendStaticNACK(unsigned int cid, uint16_t msn)
    {
		data_t options;

        SendFeedback2(cid, msn, FB_STATIC_NACK, options);
    }
    
    void
    Decompressor::SendFeedback1(unsigned int cid, uint8_t lsbMsn)
    {
		if (compressor)
		{
			data_t fbData;

			fbData.push_back(feedback | 1); // one byte msn

			/**
			 This does not follow spec,
			 in case cid == 0 and lsbMsn looks like an addCID
			 the decompressor will look at lsbMSN and believe 
			 it is a addCID. Therefore, allways use the addCID
			 */

			if (!largeCID /*&& cid*/) {
				fbData.push_back(CreateShortCID(cid));
			} else if (largeCID) {
				SDVLEncode(back_inserter(fbData), cid);
			}
			fbData.push_back(lsbMsn);
			compressor->SendFeedback(fbData.begin(), fbData.end());
		}
    }

    void 
    Decompressor::SendFeedback2(unsigned int cid, uint16_t msn, FBAckType_t type, const data_t& options)
    {
        // See RFC 4995, 5.2.4.1
		if (compressor)
		{
			data_t fbData;
			// Wait with feedback header and possible size until after CRC calc
			/*
			  always send addCID, see SendFeedback1
			  */
			if (!largeCID /*&& cid*/) {
				fbData.push_back(CreateShortCID(cid));
			}
			else if (largeCID) {
				SDVLEncode(back_inserter(fbData), cid);
			}

			// The Code/Size in the fb header starts counting after the cid
			size_t fbDataStart = fbData.size();
			fbData.push_back(static_cast<uint8_t>(type) | ((msn >> 8) & 0x3f));
			fbData.push_back(static_cast<uint8_t>(msn));
			size_t crcPos = fbData.size();
			fbData.push_back(0); // CRC 0 for now
			// Add options
			fbData.insert(fbData.end(), options.begin(), options.end());
			uint8_t crc8 = CRC8(fbData.begin(), fbData.end());
			fbData[crcPos] = crc8;

			// Add header
			size_t fbSize = fbData.size() - fbDataStart;
			data_t header;
			if (fbSize <= 7) {
				header.push_back(static_cast<uint8_t>(feedback | fbSize));
			} else {
				header.push_back(feedback);
				header.push_back(static_cast<uint8_t>(fbSize));
			}

			fbData.insert(fbData.begin(), header.begin(), header.end());
			compressor->SendFeedback(fbData.begin(), fbData.end());
		}
    }
} // ns ROHC
