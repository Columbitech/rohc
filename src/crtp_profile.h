#pragma once

#include "cprofile.h"

namespace ROHC
{
    struct udphdr;
    struct rtphdr;
    class CRTPProfile : public CProfile
    {
    public:
        CRTPProfile(Compressor* comp, uint16_t cid, const iphdr* ip);
        static uint16_t ProfileID() {return 0x0101;}
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

        void CreateIR(const iphdr* ip, const udphdr* udp, const rtphdr* rtp, data_t& output);
        void CreateCO(const iphdr* ip, const udphdr* udp, const rtphdr* rtp, data_t& output);
        
        void create_rtp_static(const rtphdr* rtp, data_t& output);
        void create_rtp_dynamic(const rtphdr* rtp, data_t& output);
        void create_csrc_list_dynchain(const rtphdr* rtp, data_t& output);
        void create_udp_regular_dynamic(const udphdr* udp, data_t& output);
        
        void create_co_common(const iphdr *ip, const rtphdr *rtp, data_t &output);
        void create_pt_0_crc3(data_t& output);
        void create_pt_0_crc7(data_t& output);
        void create_pt_1_rnd(uint32_t scaled_timestamp, bool marker, data_t& output);
        void create_pt_1_seq_id(data_t& output);
        void create_pt_1_seq_ts(uint32_t scaled_timestamp, bool marker, data_t& output);
        void create_pt_2_rnd(uint32_t scaled_timestamp, bool marker, data_t& output);
        void create_pt_2_seq_id(data_t& output);
        void create_pt_2_seq_both(uint32_t scaled_timestamp, bool marker, data_t& output);
        void create_pt_2_seq_ts(uint32_t scaled_timestamp, bool marker, data_t& output);

	void create_profile_1_7_flags1_enc(bool flags1_indicator, const iphdr* ip, data_t& output);
        void create_profile_1_flags2_enc(bool flags2_indicator, const rtphdr* rtp, data_t& output);
	void create_sdvl_sn_lsb(data_t& output) const;

	void create_variable_unscaled_timestamp(bool tss_indicator, bool tsc_indicator, const rtphdr* rtp, data_t& baseheader);

	private:
		void AdvanceState(bool calledFromFeedback, bool ack);

		bool PTChanged(const rtphdr* rtp) const
		{
			return rtp->payload_type != last_rtp.payload_type;
		}

		bool PadChanged(const rtphdr* rtp) const
		{
			return rtp->padding != last_rtp.padding;
		}

		bool ExtensionChanged(const rtphdr* rtp) const
		{
			return rtp->extension != last_rtp.extension;
		}

		bool MarkerChanged(const rtphdr* rtp) const
		{
			return rtp->marker != last_rtp.marker;
		}

	uint32_t CalculateTSStride(const rtphdr* rtp) const;

	void UpdateRtpInformation(const rtphdr* rtp);
	uint8_t control_crc3() const;


        
        struct CSRCItem
        {
            CSRCItem()
            : csrc(0),
            used(false){}
            
            CSRCItem(uint32_t csrc)
            : csrc(csrc),
            used(true){}
            
            bool operator==(uint32_t csrc) const
            {
                return used && (this->csrc == csrc);
            }
            
            uint32_t csrc;
            bool used;
        };
        
        std::vector<CSRCItem> csrc_list;
        uint16_t dport;
        uint16_t sport;
	rtphdr last_rtp;
	uint32_t last_scaled_timestamp;
	uint32_t last_ts_offset;
	unsigned int number_of_packets_with_new_ts_stride_to_send;
	uint32_t time_stride;
	WLSB<uint32_t> timestamp_window;
	uint32_t ts_stride;
        bool udp_checksum_used;


    };
    
} // ns ROHC
