#include <rohc/compressor.h>
#include <rohc/lock.h>
#include <rohc/log.h>
#include "network.h"
#include <rohc/rohc.h>
#include "cprofile.h"
#include "cuncomp_profile.h"
#include <functional>
#include <algorithm>
#include <cstring>

using namespace std;

namespace
{
    struct ContextFinder : public unary_function<const ROHC::CProfile*, bool>
    {
        ContextFinder(unsigned int profileID, const ROHC::iphdr* ip) 
        : profileID(profileID), 
        ip(ip) 
        {}
        
        bool operator()(const ROHC::CProfile* profile)
        {
            return profile && profile->Matches(profileID, ip);
        }
        
        unsigned int profileID;
        const ROHC::iphdr* ip;
    };
    
    struct OldestContextFinder : public binary_function<const ROHC::CProfile*, const ROHC::CProfile, bool> {
       bool operator()(const ROHC::CProfile* a, const ROHC::CProfile* b) {
            return a->LastUsed() < b->LastUsed();
       }
    };
} // anon ns

namespace ROHC {
    
    Compressor::Compressor(size_t maxCID, Reordering_t reorder_ratio, IPIDBehaviour_t ip_id_behaviour)
    : maxCID(maxCID)
    , contexts(0)
    , feedbackData(0)
    , feedbackMutex(allocMutex())
    , reorder_ratio(reorder_ratio)
    , ip_id_behaviour(ip_id_behaviour)
    , numberOfPacketsSent(0)
    , dataSizeUncompressed(0)
    , dataSizeCompressed(0)
    {
    
        /**
         statistics
         */
        numberOfPacketsSent = 0;
        dataSizeUncompressed = 0;
        dataSizeCompressed = 0;

        memset(statistics, 0, sizeof(statistics));

        // Make room for the uncompressed profile
        contexts.push_back(0);
    }

    Compressor::~Compressor() {
        for (contexts_t::iterator i = contexts.begin(); contexts.end() != i; ++i) {
            delete *i;
        }
        freeMutex(feedbackMutex);
    }
    
    void Compressor::compress(const uint8_t* data, size_t size, data_t& output) {
        data_t d(data, data + size);
        compress(d, output);
    }

    CProfile* Compressor::findProfile(unsigned profileId, const void* ip) {
        static const unsigned uncompressedCID = 0;
        if (CUncompressedProfile::ProfileID() == profileId) {
            if (!contexts[uncompressedCID]) {
                contexts[uncompressedCID] = CProfile::Create(this, uncompressedCID, profileId, reinterpret_cast<const iphdr*>(ip));
            }
            return contexts[uncompressedCID];
        }

        // Do we have this connection already?
        contexts_t::iterator ctx = find_if(contexts.begin() + 1, contexts.end(), ContextFinder(profileId, reinterpret_cast<const iphdr*>(ip)));

        if (contexts.end() == ctx) {
            // TODO find first null context
            // Skip the uncompressed profile
            for (ctx = contexts.begin()+1; contexts.end() != ctx; ++ctx)
            {
                if (!*ctx)
                    break;
            }

            uint16_t cid = 0;
            if (ctx != contexts.end()) {
                cid = static_cast<uint16_t>(distance(contexts.begin(), ctx));

            }
            else {
                if (contexts.size() <= maxCID) {
                    cid = static_cast<uint16_t>(contexts.size());
                    contexts.push_back(static_cast<CProfile*>(0));
                } else {
                    /**
                     * We have to remove an old profile if we get here
                     */

                    OldestContextFinder finder; 
                    // Skip the uncompressed profile
                    ctx = min_element(contexts.begin() + 1, contexts.end(), finder);
                    cid = (*ctx)->CID();
                    delete *ctx;
                }
            }

            CProfile* profile = CProfile::Create(this, cid, profileId, reinterpret_cast<const iphdr*>(ip));
            contexts[cid] = profile;
            return profile;
        }
        else {
            return *ctx;
        }
    }
    
    void Compressor::compress(const data_t& data, data_t& output)
    {
        output.reserve(data.size());
        // Take care of received feedback
        HandleReceivedFeedback();

        size_t outputInSize = output.size();
        
        size_t feedbackSize = feedbackData.size();
        
        if (feedbackSize)
        {
            ScopedLock lock(feedbackMutex);
            // Add feedback data (if exists)
            output.insert(output.end(), feedbackData.begin(), feedbackData.end());
            feedbackData.clear();
        }
        
        if (data.size() < sizeof(iphdr))
        {
            error("Not enough data for an IP header\n");
            return;
        }
        
        vector<uint8_t>::const_iterator curPos = data.begin();
        
        const iphdr* ip = reinterpret_cast<const iphdr*>(&curPos[0]);
        
        unsigned int profileId = CProfile::ProfileIDForProtocol(ip, distance(curPos, data.end()), rtpDestinations);

        CProfile* profile = findProfile(profileId, ip);
        profile->SetLastUsed(millisSinceEpoch());
        
        profile->Compress(data, output);

        ++numberOfPacketsSent;
        dataSizeUncompressed += data.size();
        dataSizeCompressed += output.size() - outputInSize;
    }
    
    void
    Compressor::SendFeedback(const_data_iterator begin, const_data_iterator end)
    {
        ScopedLock lock(feedbackMutex);
        feedbackData.insert(feedbackData.end(), begin, end);
    }
    
    void Compressor::AppendFeedback(data_t& data) {
        ScopedLock lock(feedbackMutex);
        data.insert(data.end(), feedbackData.begin(), feedbackData.end());
        feedbackData.clear();
    }

    void
    Compressor::ReceivedFeedback1(uint16_t cid, uint8_t lsbMSN)
    {
        ScopedLock lock(feedbackMutex);
        receivedFeedback1.push_back(Feedback1(cid, lsbMSN));
    }
    
    void
    Compressor::ReceivedFeedback2(uint16_t cid, uint16_t msn, ROHC::FBAckType_t ackType, const_data_iterator begin, const_data_iterator end)
    {
        ScopedLock lock(feedbackMutex);
        receivedFeedback2.push_back(Feedback2(cid, msn, ackType, begin, end));
    }

    void
    Compressor::HandleReceivedFeedback() {
        ScopedLock lock(feedbackMutex);
        while(!receivedFeedback1.empty()) {
            const Feedback1& fb(receivedFeedback1.front());
            if (fb.cid < contexts.size()) {
                CProfile* profile = contexts[fb.cid];
                if (profile) {
                    profile->AckLsbMsn(fb.lsbMSN);
                }
            }
            receivedFeedback1.pop_front();
        }

        while(!receivedFeedback2.empty()) {
            const Feedback2& fb(receivedFeedback2.front());
            if (fb.cid < contexts.size()) {
                CProfile* profile = contexts[fb.cid];
                if (profile) {
                    if (FB_ACK == fb.type) {
                        profile->AckFBMsn(fb.msn14bit);
                    } else if (FB_NACK == fb.type) {
                        profile->NackMsn(fb.msn14bit);
                    } else if (FB_STATIC_NACK == fb.type) {
                        profile->StaticNackMsn(fb.msn14bit);
                    }
                }
            }
            receivedFeedback2.pop_front();
        }

    }
    
    void
    Compressor::addRTPDestinationPort(uint16_t dport)
    {
        rtpDestinations.push_back(RTPDestination(0, rohc_htons(dport)));
    }
} // ns ROHC
