#pragma once

#include "rohc.h"
#include <vector>
#include <deque>

namespace ROHC
{
    class CProfile;
    
    struct RTPDestination
    {
        RTPDestination(uint32_t daddr, uint16_t dport)
        : daddr(daddr), dport(dport) {}
        
        bool operator==(const RTPDestination& other) const
        {
            return daddr == other.daddr && dport == other.dport;
        }
        
        uint32_t daddr;
        uint16_t dport;
    };

    
    class Compressor
    {
        typedef std::vector<CProfile*> contexts_t;

    public:
        /* CID_SMALL:
         * 1-15 simultaneous streams can be handled by the compressor/decompressor
         *
         * CID_LARGE:
         * 1-16383 streams can be handled
         *
         * mrru: Maximum Reconstructed Reception Unit.
         * Largest reconstructed unit in octets the system can handle.
         * If 0, possible segments have to be thrown away.
         */
        explicit Compressor(size_t maxCID, Reordering_t reorder_ratio, IPIDBehaviour_t ip_id_behaviour);

		~Compressor();
        
        void compress(const data_t& data, data_t& output);
        void compress(const uint8_t* data, size_t size, data_t& output);
        
        
        /**
         * this function assumes the data is formatted according to
         * RFC 4995, 5.2.4.1
         */
        void SendFeedback(const_data_iterator begin, const_data_iterator end);

        
        void AppendFeedback(data_t& data);
        /*
         * called by the decompressor
         */
        void ReceivedFeedback1(uint16_t cid, uint8_t lsbMSN);        
        /*
         * Called by the decompressor
         * crc is verified and the data is the feedback options,
         * see RFC 5225, 6.9.1
         */
        void ReceivedFeedback2(uint16_t cid, uint16_t msn, FBAckType_t acktype, const_data_iterator begin, const_data_iterator end);
  
        bool LargeCID() const {return maxCID > 15;}
                
        Reordering_t ReorderRatio() const { return reorder_ratio; }
        IPIDBehaviour_t IPIdBehaviour() const {return ip_id_behaviour;}
        
        /**
         Used by the profiles to control optimistic approach
         */
        
        // After this many packets, the compressor will advance to FO state
        unsigned int NumberOfIRPacketsToSend() const {return 5;}
        
        // After this many packets, the compressor will advance to SO state
        unsigned int NumberOfFOPacketsToSend() const {return 5;}

		void IncreasePacketCount(PacketType packetType) {++statistics[packetType];}
		size_t PacketCount(PacketType packetType) {return statistics[packetType];}
        

		// Ports in host byte order
        void addRTPDestinationPort(/*uint32_t daddr,*/ uint16_t dport);
        void removeRTPDestinationPort(/*uint32_t daddr,*/ uint16_t dport);
        
        size_t NumberOfPacketsSent() const {return numberOfPacketsSent;}
        size_t UncompressedSize() const {return dataSizeUncompressed;}
        size_t CompressedSize() const {return dataSizeCompressed;}
    private:
        CProfile* findProfile(unsigned profileId, const void* ip);

		void HandleReceivedFeedback();
        size_t maxCID;
        
        contexts_t contexts;
        
        data_t feedbackData;
		void* feedbackMutex;
        
        Reordering_t reorder_ratio;
        
        IPIDBehaviour_t ip_id_behaviour;
        
        /**
         * Statistics
         */
        size_t numberOfPacketsSent;
        size_t dataSizeUncompressed;
        size_t dataSizeCompressed;
        
        std::vector<RTPDestination> rtpDestinations;

		size_t statistics[PT_2_SEQ_TS + 1];

		struct Feedback1 {
			Feedback1(uint16_t cid, uint8_t lsbMSN) : cid(cid), lsbMSN(lsbMSN) {}
			uint16_t cid;
			uint8_t lsbMSN;
		};

		struct Feedback2 {
			Feedback2(uint16_t cid, uint16_t msn14bit, FBAckType_t type, const_data_iterator optionsBegin, const_data_iterator optionsEnd) 
				: cid(cid),
				msn14bit(msn14bit),
				type(type),
				options(optionsBegin, optionsEnd) {}
			uint16_t cid;
			uint16_t msn14bit;
			FBAckType_t type;
			data_t options;
		};

		std::deque<Feedback1> receivedFeedback1;
		std::deque<Feedback2> receivedFeedback2;
    };
    
} // ns ROHC
