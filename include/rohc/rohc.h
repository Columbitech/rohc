#pragma once

#include <stdint.h>
#include <vector>

#define ROHC_DEBUG 1

#if ROHC_DEBUG
#include <cassert>
#include <iostream>
#define RASSERT(x) assert((x))
#else
#define RASSERT(x)
#endif
#include "log.h"

namespace ROHC
{
    typedef std::vector<uint8_t> data_t;
    typedef data_t::iterator data_iterator;
    typedef data_t::const_iterator const_data_iterator;
    
    /**
     * 1110 0000
     */
    static const uint8_t padding = 0xe0;
    inline bool IsPadding (uint8_t c) { return padding == c;}

    /**
     * 1110 nnnn
     * nnnn = CID if small CID
     */
    static const uint8_t addCID = 0xe0;
    static const uint8_t addCIDMask = 0xf0;

    inline bool IsAddCID (uint8_t c) { return (c & addCIDMask) == addCID;}
    inline uint8_t UnmaskShortCID (uint8_t c) { return c & 0xf;} 
    inline uint8_t CreateShortCID(uint16_t cid) 
    { 
        return static_cast<uint8_t>(0xe0 | (cid & 0x0f));
    }

    /**
     * 1111 0xxx 
     */
    static const uint8_t feedback = 0xf0;
    static const uint8_t feedbackMask = 0xf8;
    
    inline bool IsFeedback (uint8_t c) {return (c & feedbackMask) == feedback;}
    inline uint8_t UnmaskFeedback(uint8_t c) {return c & 0x07;}
    inline uint8_t CreateFeedback(uint8_t code) {return static_cast<uint8_t>(feedback | (code & 7));}

    /**
     * 1111 1000
     */
    static const uint8_t IR_DYNPacket = 0xf8;
    inline bool IsIR_DYN(uint8_t c) {return c == IR_DYNPacket;}
    
    /**
     * 1111 110x
     */
    static const uint8_t IRPacketMask = 0xfe;
    static const uint8_t IRPacket = 0xfc;
    static const uint8_t IRv2Packet = 0xfd; // 1111 1101
    inline bool IsIR(uint8_t c) {return (c & IRPacketMask) == IRPacket;}
    inline uint8_t CreateIR(unsigned int res) {return static_cast<uint8_t>(IRPacket | (res & 1));}
    
    /**
     * 1111 111x
     */
    static const uint8_t segment = 0xfe;
    inline bool isSegment(uint8_t c) {return (c & segment) == segment;}

    /**
     * 1111 1011
     */
    static const uint8_t CORepairPacket = 0xfb;
    inline bool IsCORepairPacket(uint8_t c) { return c == CORepairPacket;}
    
	enum PacketType
	{
		PT_IR,
		PT_CO_COMMON,
		PT_0_CRC3,
		PT_0_CRC7,
		PT_1_RND,
		PT_1_SEQ_ID,
		PT_1_SEQ_TS,
		PT_2_RND,
		PT_2_SEQ_ID,
		PT_2_SEQ_BOTH,
		PT_2_SEQ_TS
	};
    
    
    /**
     * ROHC constants
     * RFC 5225
     * 6.8.2.4
     */
    
    // RFC 5225, 6.3.3
    enum IPIDBehaviour_t
    {
        IP_ID_BEHAVIOUR_SEQUENTIAL          = 0, // network byte order
        IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED  = 1, // byte swapped
        IP_ID_BEHAVIOUR_RANDOM              = 2,
        IP_ID_BEHAVIOUR_ZERO                = 3
    };    
    
    enum Reordering_t
    {
        REORDERING_NONE             = 0,
        REORDERING_QUARTER          = 1,
        REORDERING_HALF             = 2,
        REORDERING_THREEQUARTERS    = 3
    };
    
    enum FBAckType_t
    {
        FB_ACK = 0,
        FB_NACK = 0x40,
        FB_STATIC_NACK = 0x80
    };

	enum FBOption_t {
		FBO_REJECT = 0x20,
		FBO_ACKNUMBER_NOT_VALID = 0x30,
		FBO_CONTEXT_MEMORY = 0x90,
		FBO_CLOCK_RESOLUTION = 0xa0
	};
    
    static const uint32_t TS_STRIDE_DEFAULT = 160;
    static const uint32_t TIME_STRIDE_DEFAULT = 0;
    
    /* 
     * Self describing Variable-Length Values
     * RFC 4995, 5.3.2
     */
    
    inline size_t 
    SDVLSize(uint32_t f)
    {
        if ((f & 0x80) == 0)
            return 1;
        else if ((f & 0xc0) == 0x80)
            return 2;
        else if ((f & 0xe0) == 0xc0)
            return 3;
        else if ((f & 0xe0) == 0xe0)
            return 4;
        
        error("SDVLSize, unknown size\n");
        return 0;
    }

    
    template<class T>
    inline bool
    SDVLDecode(T& pos, T end, uint32_t* value)
    {
        if (std::distance(pos, end) < 1) {
            error("SDVLDecode, cannot read first byte\n");
            return false;
        }
        uint32_t first = *pos++;
        size_t size = SDVLSize(first);
        
        if (std::distance(pos, end) < static_cast<int>(size - 1)) {
            error("SDVLDecode, not enough data\n");
            return false;
        }
        
        if (1 == size) // One byte
        {
            *value = (first & 0x7f);
        }
        else if (2 == size) // Two bytes
        {
			*value = (first & 0x3f) << 8;
			*value |= *pos++;
        }
        else if (3 == size) // Three bytes
        {
            *value = (first & 0x1f) << 16;
            *value |= (*pos++) << 8;
            *value |= *pos++;
        }
        else // four bytes
        {
            *value = (first & 0x1f) << 24;
            *value |= (*pos++) << 16;
            *value |= (*pos++) << 8;
            *value |= *pos++;
        }
        
        return true;
    }
    
    template<class T>
    inline T 
    SDVLEncode(T pos, uint32_t value)
    {
        if (!(value <= 0x1fffffff)) {
            error("SDVLEncode, not a valid value\n");
        }
        
        if (value < 128)
        {
            uint8_t val = static_cast<uint8_t>(value);
            *pos++ = val;
        }
        else if (value < 16384)
        {
            uint8_t val = static_cast<uint8_t>(value >> 8) | 0x80;
            *pos++ = val;
            *pos++ = static_cast<uint8_t>(value);
        }
        else if (value < 2097152)
        {
            uint8_t val = static_cast<uint8_t>(value >> 16) | 0xc0;
            *pos++ = val;
            *pos++ = static_cast<uint8_t>(value >> 8);
            *pos++ = static_cast<uint8_t>(value);
        }
        else
        {
            uint8_t val = static_cast<uint8_t>(value >> 24) | 0xe0;
            *pos++ = val;
            *pos++ = static_cast<uint8_t>(value >> 16);
            *pos++ = static_cast<uint8_t>(value >> 8);
            *pos++ = static_cast<uint8_t>(value);            
        }
        
        return pos;
    }
        
    /**
     Print functions
     */
    
    void PrintState(uint16_t msn, Reordering_t rr, IPIDBehaviour_t ipbehav);
    void PrintData(const_data_iterator begin, const_data_iterator end);
    void PrintCompareData(const_data_iterator begin1, const_data_iterator end1, const_data_iterator begin2);
    
    /**
     * CRC functions
     */
    void CRCInit();
    uint8_t CRC3(const_data_iterator begin, const_data_iterator end);
	uint8_t CRC3(const uint8_t* begin, const uint8_t* end);
    uint8_t CRC7(const_data_iterator begin, const_data_iterator end);        
	uint8_t CRC7(const uint8_t* begin, const uint8_t* end);
    uint8_t CRC8(const_data_iterator begin, const_data_iterator end);        
    
    
    time_t millisSinceEpoch();
    
    /**
     data functions
     */
       
    
    template<class T>
    void AppendData(data_t& data, const T& value)
    {
        const uint8_t* p8 = reinterpret_cast<const uint8_t*>(&value);
        data.insert(data.end(), p8, p8 + sizeof(T));
    }
    
    inline void AppendDataToNBO(data_t& data, uint32_t value)
    {
        data.push_back(static_cast<uint8_t>(value >> 24));
        data.push_back((value >> 16) & 0xff);
        data.push_back((value >> 8) & 0xff);
        data.push_back(value & 0xff);
    }

    inline void AppendDataToNBO(data_t& data, uint16_t value)
    {
        data.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
        data.push_back(static_cast<uint8_t>(value & 0xff));
    }
    
    template<class T, class Iter>
    bool GetValue(Iter& pos, const Iter end, T& value)
    {
        if ((end - pos) < static_cast<int>(sizeof(T))) {
            return false;
        }
        value = *reinterpret_cast<const T*>(&*pos);
        pos += sizeof(T);
        return true;
    }
    
    template<class Iter>
    bool GetValueFromNBO(Iter& pos, const Iter end, uint16_t& value)
    {
        if ((end - pos) < static_cast<int>(sizeof(uint16_t))) {
            return false;
        }
        // TODO fix big endian
        const uint8_t* p8 = reinterpret_cast<const uint8_t*>(&*pos);
        value = (p8[0] << 8) | p8[1];
		pos += sizeof(uint16_t);
        return true;
    }
    
} // namespace ROHC

