#pragma once

#include "rohc.h"
#include <map>

namespace ROHC
{
    class Compressor;
    class DProfile;
    
    class Decompressor
    {
    private:
        void operator=(const Decompressor&);
        Decompressor();
        Decompressor(const Decompressor&);

        typedef std::map<uint32_t, DProfile*> context_t;
    public:
        Decompressor(bool largeCID, Compressor* compressor);
        ~Decompressor();
        
        bool LargeCID() const {return largeCID;}
        
        
        void Decompress(const uint8_t* data, size_t dataSize, data_t& output);
        /**
         * when decompressing the function will temporarily modify
         * the data (as part of CRC verification), therefore not marked as const
         */
        void Decompress(data_t& data, data_t& output);
        
        
        /*
         * The send FB functions will modify the data to add correct headers
         */
        void SendACK(unsigned int cid, uint16_t msn);
        void SendNACK(unsigned int cid, uint16_t msn);
		void SendStaticNACK(unsigned int cid);
        void SendStaticNACK(unsigned int cid, uint16_t msn);

        void SendFeedback1(unsigned int cid, uint8_t lsbMsn);

    private:
        bool ParseFeedback(data_t& data, data_iterator& pos);
        
        /**
         * irType is the unmasked value from the ir header
         * start of the header
         */
        void ParseIR(data_t& data, data_iterator irDataStart, data_t& output);
        void ParseCO(data_t& data, data_iterator pos, data_t& output);
        void ParseCORepair(data_t& data, data_iterator pos, data_t& output);
        
        void SendFeedback2(unsigned int cid, uint16_t msn, FBAckType_t type, const data_t& options);
    private:
        Compressor* compressor;
        bool largeCID;
        
        context_t contexts;
        
        /**
         * Statistics
         */
        unsigned int numberOfPacketsReceived;
        size_t dataSizeUncompressed;
        size_t dataSizeCompressed;
    };
    
} // ns ROHC