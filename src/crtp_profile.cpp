#include "crtp_profile.h"
#include "cudp_profile.h"
#include "network.h"
#include <rohc/compressor.h>
#include <iterator>
#include <cstring>

using namespace std;

namespace ROHC
{
    CRTPProfile::CRTPProfile(Compressor* comp, uint16_t cid, const iphdr* ip)
    : CProfile(comp, cid, ip)
    , csrc_list(16)
	, number_of_packets_with_new_ts_stride_to_send(0)
	, timestamp_window(16, 16, 0)
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
        sport = udp->source;
        dport = udp->dest;
        const rtphdr* rtp = reinterpret_cast<const rtphdr*>(udp+1);
        RASSERT(rtp->version == 2);
        msn = rtp->sequence_number;
		ts_stride = TS_STRIDE_DEFAULT;
		time_stride = TIME_STRIDE_DEFAULT;
    }
    
    bool
    CRTPProfile::Matches(unsigned int profileID, const ROHC::iphdr *ip) const
    {
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
        return (profileID == ID()) &&
        (saddr == ip->saddr) &&
        (sport == udp->source) &&
        (daddr == ip->daddr) &&
        (dport == udp->dest);        
    }
    
    void
    CRTPProfile::Compress(const data_t &data, data_t &output)
    {
        size_t outputInSize = output.size();
        const iphdr* ip = reinterpret_cast<const iphdr*>(&data[0]);
        const udphdr* udp = reinterpret_cast<const udphdr*>(ip+1);
        const rtphdr* rtp = reinterpret_cast<const rtphdr*>(udp+1);
        

		// MSN should always be the sequence number of rtp
		msn = rohc_htons(rtp->sequence_number);

		UpdateIpIdOffset(ip);
        
		uint32_t calculated_ts_stride = CalculateTSStride(rtp);

		if (calculated_ts_stride &&
			(ts_stride != calculated_ts_stride))
		{
			number_of_packets_with_new_ts_stride_to_send = 5;
			ts_stride = calculated_ts_stride;
		}

		//cout << "Calculated time_stride: " << calculated_ts_stride << endl;

        if (IR_State == state)
        {
            CreateIR(ip, udp, rtp, output);
        }
        else
        {
            CreateCO(ip, udp, rtp, output);
        }

		// Decrease this after packet it sent
		if (number_of_packets_with_new_ts_stride_to_send > 0)
		{
			--number_of_packets_with_new_ts_stride_to_send;
            /*
			if (0 == number_of_packets_with_new_ts_stride_to_send)
			{
				timestamp_window.clear();
			}
             */
		}

		UpdateIpInformation(ip);
		UpdateRtpInformation(rtp);

        AdvanceState(false, false);
        msnWindow.add(msn, msn);
        
        // Append payload
        output.insert(output.end(), data.begin() + sizeof(iphdr) + sizeof(udphdr) + sizeof(rtphdr), data.end());
        
        ++numberOfPacketsSent;
        dataSizeCompressed += output.size() - outputInSize;
        dataSizeUncompressed += data.size();        
    }
    
    void
    CRTPProfile::CreateIR(const ROHC::iphdr *ip, const ROHC::udphdr *udp, const ROHC::rtphdr *rtp, data_t &output)
    {
        size_t headerStartIdx = output.size();
        
        if (!largeCID && cid)
        {
            output.push_back(CreateShortCID(cid));
        }
        
        output.push_back(IRv2Packet);
        
        if (largeCID)
        {
            SDVLEncode(back_inserter(output), cid);
        }
        
        output.push_back(static_cast<uint8_t>(ProfileID()));
        
        size_t crcPos = output.size();
        
        // Add zero crc for now
        output.push_back(0);
        
        create_ipv4_static(ip, output);
        
        CUDPProfile::create_udp_static(sport, dport, output);
        
        create_rtp_static(rtp, output);
        
        create_ipv4_regular_innermost_dynamic(ip, output);
        
        create_udp_regular_dynamic(udp, output);
        
        create_rtp_dynamic(rtp, output);
        
        // Calculate CRC
        
        uint8_t crc = CRC8(output.begin() + headerStartIdx, output.end());
        //cout << "CRTPProfile::CreateIR: crcSize: " << crcSize << " crc: " << (size_t) crc << endl;
        output[crcPos] = crc;
        
        IncreasePacketCount(PT_IR);
        ++numberOfIRPacketsSent;
        ++numberOfIRPacketsSinceReset;        
    }
    
    void
    CRTPProfile::CreateCO(const ROHC::iphdr *ip, const ROHC::udphdr *udp, const ROHC::rtphdr *rtp, data_t &output)
    {
        data_t baseheader;
        
        unsigned int neededMSNWidth = msnWindow.width(msn);

		//cout << "Needed MSN: " << neededMSNWidth << endl;
        
		uint32_t host_timestamp = rohc_htonl(rtp->timestamp);

		bool markerChanged =  MarkerChanged(rtp);

		// If ts follows the rule delta-SN * ts_stride + old_ts = new_ts, we can compress hard
		bool inferred_scaled_ts_possible = host_timestamp == (rohc_htonl(last_rtp.timestamp) + ts_stride * (msn - rohc_htons(last_rtp.sequence_number)));
        uint32_t scaled_timestamp = host_timestamp / ts_stride;
		int neededTSWidth = timestamp_window.width(scaled_timestamp);

		uint32_t ts_offset = host_timestamp % ts_stride;
		bool ts_offset_changed = ts_offset != last_ts_offset;

		bool basic = !TOSChanged(ip) && !TTLChanged(ip) && !PTChanged(rtp) && !PadChanged(rtp) && !ExtensionChanged(rtp);

		bool pt_0_crc3_possible = basic && (neededMSNWidth <= 4) && inferred_scaled_ts_possible && !markerChanged;
		bool pt_0_crc7_possible = basic && (neededMSNWidth <= 5) && inferred_scaled_ts_possible && !markerChanged;

		// If ts_stride has changed, we always go with co_common
		if ((number_of_packets_with_new_ts_stride_to_send > 0) ||
			(FO_State == state))
		{
			create_co_common(ip, rtp, baseheader);
		}
		else if ( (IP_ID_BEHAVIOUR_RANDOM == ip_id_behaviour) ||
			(IP_ID_BEHAVIOUR_ZERO == ip_id_behaviour))
		{
			bool pt_1_rnd_possible = basic && (neededMSNWidth <= 4) && (neededTSWidth <= 5) && !ts_offset_changed;
			bool pt_2_rnd_possible = basic && (neededMSNWidth <= 7) && (neededTSWidth <= 6) && !ts_offset_changed;

			if (pt_0_crc3_possible)
			{
				//cout << "pt_0_crc3" << endl;
				create_pt_0_crc3(baseheader);
			}
			else if (pt_0_crc7_possible)
			{
				//cout << "pt_0_crc7" << endl;
				create_pt_0_crc7(baseheader);
			}
			else if (pt_1_rnd_possible)
			{
				//cout << "pt_1_rnd" << endl;
				create_pt_1_rnd(scaled_timestamp, rtp->marker > 0, baseheader);
			}
			else if (pt_2_rnd_possible)
			{
				//cout << "pt_2_rnd_possible" << endl;
				create_pt_2_rnd(scaled_timestamp, rtp->marker > 0, baseheader);
			}
			else
			{
				create_co_common(ip, rtp, baseheader);
			}
		}
		else
		{
			unsigned int neededIPIDWidth = IpIdOffsetWidth();
			//cout << "neededIPIDWidth: " << neededIPIDWidth << endl;

			if (IPIDOffsetChanged())
			{
				//cout << "ip id offset changed" << endl;
			}

			pt_0_crc3_possible = pt_0_crc3_possible && !IPIDOffsetChanged();
			pt_0_crc7_possible = pt_0_crc7_possible && !IPIDOffsetChanged();

			bool pt_1_seq_id_possible = basic && (neededIPIDWidth <= 4) && (neededMSNWidth <= 5) && !markerChanged && (neededTSWidth == 0);
			bool pt_1_seq_ts_possible = basic && !IPIDOffsetChanged() && (neededMSNWidth <= 4) && (neededTSWidth <= 5) && !ts_offset_changed;
			bool pt_2_seq_id_possible = basic && (neededIPIDWidth <= 5) && (neededMSNWidth <= 7) && !markerChanged  && (neededTSWidth == 0);
			bool pt_2_seq_both_possible = basic && (neededIPIDWidth <= 5) && (neededMSNWidth <= 7) && (neededTSWidth <= 7) && !ts_offset_changed;
			bool pt_2_seq_ts_possible = basic && !IPIDOffsetChanged() && (neededMSNWidth <= 7) && (neededTSWidth <= 5) && !ts_offset_changed;

			if (pt_0_crc3_possible)
			{
				//cout << "pt_0_crc3" << endl;
				create_pt_0_crc3(baseheader);
			}
			else if (pt_0_crc7_possible)
			{
				//cout << "pt_0_crc7" << endl;
				create_pt_0_crc7(baseheader);
			}
			else if (pt_1_seq_id_possible)
			{
				//cout << "pt_1_seq_id" << endl;
				create_pt_1_seq_id(baseheader);
			}
			else if (pt_1_seq_ts_possible)
			{
				//cout << "pt_1_seq_ts_possible" << endl;
				create_pt_1_seq_ts(scaled_timestamp, rtp->marker > 0, baseheader);
			}
			else if (pt_2_seq_id_possible)
			{
				//cout << "pt_2_seq_id_possible" << endl;
				create_pt_2_seq_id(baseheader);
			}
			else if (pt_2_seq_ts_possible)
			{
				//cout << "pt_2_seq_ts_possible" << endl;
				create_pt_2_seq_ts(scaled_timestamp, rtp->marker, baseheader);
			}
			else if (pt_2_seq_both_possible)
			{
				//cout << "pt_2_seq_both_possible" << endl;
				create_pt_2_seq_both(scaled_timestamp, rtp->marker > 0, baseheader);
			}
			else
			{
				create_co_common(ip, rtp, baseheader);
			}
		}
        
        if (!largeCID && cid)
        {
            output.push_back(CreateShortCID(cid));
        }
        
        output.push_back(baseheader[0]);
        
        if (largeCID)
        {
            SDVLEncode(back_inserter(output), cid);
        }
        
        output.insert(output.end(), baseheader.begin() + 1, baseheader.end());
        
        create_ipv4_innermost_irregular(ip, output);
        if (udp_checksum_used)
            CUDPProfile::create_udp_with_checksum_irregular(udp, output);
        
        
        if (FO_State == state)
        {
            ++numberOfFOPacketsSent;
            ++numberOfFOPacketsSinceReset;
        }
        else
        {
            ++numberOfSOPacketsSent;
        }        
    }
    
    /*
     COMPRESSED rtp_static {
        ssrc =:= irregular(32) [ 32 ];
     }
     */
    void
    CRTPProfile::create_rtp_static(const ROHC::rtphdr *rtp, data_t &output)
    {
        AppendData(output, rtp->ssrc);
    }
    
    /*
	p. 65
     COMPRESSED rtp_dynamic {
         reserved =:= compressed_value(1, 0)            [ 1 ];
         reorder_ratio =:= irregular(2)                 [ 2 ];
         list_present =:= irregular(1)                  [ 1 ];
         tss_indicator =:= irregular(1)                 [ 1 ];
         tis_indicator =:= irregular(1)                 [ 1 ];
         pad_bit =:= irregular(1)                       [ 1 ];
         extension =:= irregular(1)                     [ 1 ];
         marker =:= irregular(1)                        [ 1 ];
         payload_type =:= irregular(7)                  [ 7 ];
         sequence_number =:= irregular(16)              [ 16 ];
         timestamp =:= irregular(32)                    [ 32 ];
         ts_stride =:= sdvl_or_default(tss_indicator.CVALUE,
         TS_STRIDE_DEFAULT)                             [ VARIABLE ];
         time_stride =:= sdvl_or_default(tis_indicator.CVALUE,
             TIME_STRIDE_DEFAULT)                       [ VARIABLE ];
         csrc_list =:= csrc_list_dynchain(list_present.CVALUE,
             cc.UVALUE)                                 [ VARIABLE ];
     }
     */
    void
    CRTPProfile::create_rtp_dynamic(const ROHC::rtphdr *rtp, data_t &output)
    {
        uint8_t res_reorder_ratio_flags = static_cast<uint8_t>(((reorder_ratio & 3) << 5));
        bool list_present = false; //rtp->csrc_count > 0;
        if (list_present)
        {
            res_reorder_ratio_flags |= 0x10;
        }

        bool tss_indicator = number_of_packets_with_new_ts_stride_to_send > 0;
        if (tss_indicator)
        {
            res_reorder_ratio_flags |= 0x08;
        }
        
        bool tis_indicator = false;
        if (tis_indicator)
        {
            res_reorder_ratio_flags |= 0x04;
        }
        
        bool pad_bit = rtp->padding;
        if (pad_bit)
        {
            res_reorder_ratio_flags |= 0x02;
        }
        
        bool extension = rtp->extension;
        if (extension)
        {
            res_reorder_ratio_flags |= 0x01;
        }
        
        output.push_back(res_reorder_ratio_flags);
        
        uint8_t marker_pt = static_cast<uint8_t>(((rtp->marker) << 7) | (rtp->payload_type & 0x7f));
        
        output.push_back(marker_pt);
        
        AppendData(output, rtp->sequence_number);
        AppendData(output, rtp->timestamp);
        if (tss_indicator)
        {
            SDVLEncode(back_inserter(output), ts_stride);
        }
        
        if (tis_indicator)
        {
            // TODO, find out time_stride
            uint32_t time_stride = TIME_STRIDE_DEFAULT;
            SDVLEncode(back_inserter(output), time_stride);            
        }
        
        if (list_present)
        {
            create_csrc_list_dynchain(rtp, output);
        }        
    }
    
    void
    CRTPProfile::create_csrc_list_dynchain(const rtphdr *rtp, data_t& output)
    {
        /*
        unsigned int csrc_count = rtp->csrc_count;
        uint8_t res_ps_m = csrc_count; // use 4 bit size
        output.push_back(res_ps_m);
        const uint32_t* pcsrc = reinterpret_cast<const uint32_t*>(rtp+1);
        
        vector<size_t> newIndices;
        uint8_t xi = 0;
        for(unsigned int i = 0; i < csrc_count; ++i)
        {
            vector<CSRCItem>::iterator c = find(csrc_list.begin(), csrc_list.end(), pcsrc[i]);
            
        }
         */
	(void)rtp;
	(void)output;
    }
    
    void
    CRTPProfile::create_udp_regular_dynamic(const ROHC::udphdr *udp, data_t& output)
    {
        udp_checksum_used = udp->check != 0;
        AppendData(output, udp->check);
    }

	uint8_t
	CRTPProfile::control_crc3() const
	{
		data_t data;

		data.push_back(static_cast<uint8_t>(reorder_ratio) & 0x03);
		AppendDataToNBO(data, ts_stride);
		AppendDataToNBO(data, time_stride);
		return CRC3(data.begin(), data.end());
	}
    
    /*
	Page 80
     // Replacement for UOR-2-ext3
     COMPRESSED co_common {
         ENFORCE(outer_ip_flag == outer_ip_indicator.CVALUE);
         discriminator =:= ’11111010’                                     [ 8 ];
     
         marker =:= irregular(1)                                          [ 1 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)                   [ 7 ];
     
         flags1_indicator =:= irregular(1)                                [ 1 ];
         flags2_indicator =:= irregular(1)                                [ 1 ];
         tsc_indicator =:= irregular(1)                                   [ 1 ];
         tss_indicator =:= irregular(1)                                   [ 1 ];
         ip_id_indicator =:= irregular(1)                                 [ 1 ];
         control_crc3 =:= control_crc3_encoding                           [ 3 ];
     
         outer_ip_indicator : ttl_hopl_indicator :
           tos_tc_indicator : df : ip_id_behavior_innermost : reorder_ratio
           =:= profile_1_7_flags1_enc(flags1_indicator.CVALUE,
               ip_version.UVALUE)                                         [0, 8];
         list_indicator : pt_indicator : tis_indicator : pad_bit :
           extension =:= profile_1_flags2_enc(
           flags2_indicator.CVALUE)                                       [0, 8];
         tos_tc =:= static_or_irreg(tos_tc_indicator.CVALUE, 8)           [0, 8];
         ttl_hopl =:= static_or_irreg(ttl_hopl_indicator.CVALUE,
            ttl_hopl.ULENGTH)                                             [0, 8];
         payload_type =:= pt_irr_or_static(pt_indicator)                  [0, 8];
         sequence_number =:=
            sdvl_sn_lsb(sequence_number.ULENGTH)                    [ VARIABLE ];
         ip_id =:= ip_id_sequential_variable(
            ip_id_behavior_innermost.UVALUE,
            ip_id_indicator.CVALUE)                                 [ 0, 8, 16 ];
         ts_scaled =:= variable_scaled_timestamp(tss_indicator.CVALUE,
           tsc_indicator.CVALUE, ts_stride.UVALUE,
           time_stride.UVALUE)                                      [ VARIABLE ];
         timestamp =:= variable_unscaled_timestamp(tss_indicator.CVALUE,
           tsc_indicator.CVALUE)                                    [ VARIABLE ];
         ts_stride =:= sdvl_or_static(tss_indicator.CVALUE)         [ VARIABLE ];
         time_stride =:= sdvl_or_static(tis_indicator.CVALUE)       [ VARIABLE ];
         csrc_list =:= csrc_list_presence(list_indicator.CVALUE,
           cc.UVALUE)                                               [ VARIABLE ];
     }
     */
    void
    CRTPProfile::create_co_common(const iphdr *ip, const rtphdr *rtp, data_t &baseheader)
    {
		IncreasePacketCount(PT_CO_COMMON);
        baseheader.push_back(0xfa); // discriminator
        size_t crcIdx = baseheader.size();
        baseheader.push_back(static_cast<uint8_t>(rtp->marker << 7)); // marker and crc 0
        
        uint8_t flags_crc3 = 0;
        //uint8_t profile_1_7_flags1 = 0;
        
        bool flags1_indicator = DFChanged(ip) || TTLChanged(ip) || TOSChanged(ip);
        // TODO, check if ip_id_behaviour or reorder_ratio has changed
        if (flags1_indicator)
        {
            flags_crc3 |= 0x80;
        }
        
		bool list_indicator = false;
		bool tis_indicator = false;
        bool flags2_indicator = list_indicator || PTChanged(rtp) || tis_indicator || PadChanged(rtp) || ExtensionChanged(rtp);
        // TODO, check if csrc list, pt, time_stride, pad or extension has changed
        if (flags2_indicator)
        {
            flags_crc3 |= 0x40;
        }

		bool tsc_indicator = false;
		if (tsc_indicator)
		{
			flags_crc3 |= 0x20;
		}

		bool tss_indicator = number_of_packets_with_new_ts_stride_to_send > 0;
		if (tss_indicator)
		{
			flags_crc3 |= 0x10;
		}

		bool ip_id_indicator = (ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED) &&
			(IpIdOffsetWidth() > 8);
		if (ip_id_indicator )
		{
			flags_crc3 |= 0x08;
		}
        
		flags_crc3 |= control_crc3();

		baseheader.push_back(flags_crc3);

        create_profile_1_7_flags1_enc(flags1_indicator, ip, baseheader);
		create_profile_1_flags2_enc(flags2_indicator, rtp, baseheader);

		if (TOSChanged(ip))
		{
			baseheader.push_back(ip->tos);
		}

		if (TTLChanged(ip))
		{
			baseheader.push_back(ip->ttl);
		}

		if (PTChanged(rtp))
		{
			baseheader.push_back(static_cast<uint8_t>(rtp->payload_type));
		}

		create_sdvl_sn_lsb(baseheader);

		ip_id_sequential_variable(ip_id_indicator, ip, baseheader);

		create_variable_unscaled_timestamp(tss_indicator, tsc_indicator, rtp, baseheader);

		if (tss_indicator)
		{
			SDVLEncode(back_inserter(baseheader), ts_stride);
		}

		if (tis_indicator)
		{
			//...
		}

		if (list_indicator)
		{
		}
		// crc7 from idx of crc minus one (the discriminator)
		uint8_t crc7 = CRC7(baseheader.begin() + crcIdx - 1, baseheader.end());

		baseheader[crcIdx] |= crc7 & 0x7f;
    }
    
    /*
     // UO-0
     COMPRESSED pt_0_crc3 {
         discriminator =:= ’0’                              [ 1 ];
         msn =:= msn_lsb(4)                                 [ 4 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH)     [ 3 ];
         timestamp =:= inferred_scaled_field                [ 0 ];
         ip_id =:= inferred_sequential_ip_id                [ 0 ];
     }
     */
    void
    CRTPProfile::create_pt_0_crc3(data_t &output)
    {
		IncreasePacketCount(PT_0_CRC3);
        uint8_t disc_msn_crc = static_cast<uint8_t>((msn & 0x0f) << 3);
        uint8_t crc3 = CRC3(&disc_msn_crc, &disc_msn_crc + 1);
		output.push_back(disc_msn_crc | crc3);
    }
    
    /*
     // New format, Type 0 with strong CRC and more SN bits
     COMPRESSED pt_0_crc7 {
         discriminator =:= ’1000’                           [ 4 ];
         msn =:= msn_lsb(5)                                 [ 5 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)     [ 7 ];
         timestamp =:= inferred_scaled_field                [ 0 ];
         ip_id =:= inferred_sequential_ip_id                [ 0 ];
     }
     */
    void 
    CRTPProfile::create_pt_0_crc7(data_t &output)
    {
		IncreasePacketCount(PT_0_CRC7);
		
		output.resize(2);

        output[0] = static_cast<uint8_t>(0x80 + ((msn >> 1) & 0x0f));

		output[1] = static_cast<uint8_t>(msn << 7);
		uint8_t crc7 = CRC7(output.begin(), output.end());
		output[1] |= crc7;
    }
    
    /*
     // UO-1 replacement
     COMPRESSED pt_1_rnd {
         ENFORCE(ts_stride.UVALUE != 0);
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
                IP_ID_BEHAVIOR_RANDOM) ||
                (ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_ZERO));
         discriminator =:= ’101’                                [ 3 ];
         marker =:= irregular(1)                                [ 1 ];
         msn =:= msn_lsb(4)                                     [ 4 ];
         ts_scaled =:= scaled_ts_lsb(time_stride.UVALUE, 5)     [ 5 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH)         [ 3 ];
     }
     */
    void
    CRTPProfile::create_pt_1_rnd(uint32_t scaled_timestamp, bool marker, data_t &output)
    {
		IncreasePacketCount(PT_1_RND);
        // TODO, check ts_strid != 0;
        //        RASSERT(
        RASSERT(IP_ID_BEHAVIOUR_ZERO == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_RANDOM == ip_id_behaviour);

		uint8_t lsbMsn = msn & 0x0f;

		output.resize(2);
		output[0] = 0xa0 | lsbMsn;
		if (marker)
			output[0] |= 0x10;

		uint8_t lsbTS = scaled_timestamp & 0x1f;
		output[1] = lsbTS << 3;
		uint8_t crc3 = CRC3(output.begin(), output.end());
		output[1] |= crc3;
    }
    
    /*
     // UO-1-ID replacement
     COMPRESSED pt_1_seq_id {
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
            IP_ID_BEHAVIOR_SEQUENTIAL) ||
            (ip_id_behavior_innermost.UVALUE ==
            IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’1001’                                   [ 4 ];
         ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 4)    [ 4 ];
         msn =:= msn_lsb(5)                                         [ 5 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH)             [ 3 ];
         timestamp =:= inferred_scaled_field                        [ 0 ];
     }
     */
    void
    CRTPProfile::create_pt_1_seq_id(data_t &output)
    {
		IncreasePacketCount(PT_1_SEQ_ID);
        RASSERT(IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour);
		
		output.resize(2);
		output[0] = 0x90 | (IpIdOffset() & 0x0f);
		output[1] = static_cast<uint8_t>(msn << 3);
		uint8_t crc3 = CRC3(output.begin(), output.end());
		output[1] |= crc3;
    }
    
    /*
     // UO-1-TS replacement
     COMPRESSED pt_1_seq_ts {
         ENFORCE(ts_stride.UVALUE != 0);
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL) ||
                 (ip_id_behavior_innermost.UVALUE ==
                 IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’101’                                [ 3 ];
         marker =:= irregular(1)                                [ 1 ];
         msn =:= msn_lsb(4)                                     [ 4 ];
         ts_scaled =:= scaled_ts_lsb(time_stride.UVALUE, 5)     [ 5 ];
         header_crc =:= crc3(THIS.UVALUE, THIS.ULENGTH)         [ 3 ];
         ip_id =:= inferred_sequential_ip_id                    [ 0 ];
     }
     */
    void
    CRTPProfile::create_pt_1_seq_ts(uint32_t scaled_timestamp, bool marker, data_t &output)
    {
		IncreasePacketCount(PT_1_SEQ_TS);
        RASSERT(IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour);
		
		output.resize(2);

		output[0] = 0xa0;
		if (marker)
			output[0] = 0xb0 | (msn & 0x0f);
		else
			output[0] = 0xa0 | (msn & 0x0f);

		output[1] = (scaled_timestamp & 0x1f) << 3;
		output[1] |= CRC3(output.begin(), output.end());
    }
    
    /*
     // UOR-2 replacement
     COMPRESSED pt_2_rnd {
         ENFORCE(ts_stride.UVALUE != 0);
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
             IP_ID_BEHAVIOR_RANDOM) ||
             (ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_ZERO));
         discriminator =:= ’110’                                [ 3 ];
         msn =:= msn_lsb(7)                                     [ 7 ];
         ts_scaled =:= scaled_ts_lsb(time_stride.UVALUE, 6)     [ 6 ];
         marker =:= irregular(1)                                [ 1 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)         [ 7 ];
     }
     */
    void
    CRTPProfile::create_pt_2_rnd(uint32_t scaled_timestamp, bool marker, data_t &output)
    {
		IncreasePacketCount(PT_2_RND);   
		output.resize(3);

		uint8_t lsbMsn = msn & 0x7f;
		output[0] = 0xc0 | (lsbMsn >> 2);
		uint8_t scaled_ts_lsb = scaled_timestamp & 0x3f;
		output[1] = (lsbMsn << 6) | scaled_ts_lsb;
		if (marker)
			output[2] = 0x80;
		
		uint8_t crc7 = CRC7(output.begin(), output.end());
		output[2] |= crc7;

		//cout << "TS scaled: " << hex << scaled_timestamp << dec << endl;
		//cout << "lsb ts: " << hex << (unsigned) scaled_ts_lsb << dec << endl;
		//cout << "msn: " << hex << msn << " lsb: " << (unsigned) lsbMsn << dec << endl;
    }
    
    /*
     // UOR-2-ID replacement
     COMPRESSED pt_2_seq_id {
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
             IP_ID_BEHAVIOR_SEQUENTIAL) ||
             (ip_id_behavior_innermost.UVALUE ==
             IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’11000’                                  [ 5 ];
         msn =:= msn_lsb(7)                                         [ 7 ];
         ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 5)    [ 5 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)             [ 7 ];
         timestamp =:= inferred_scaled_field                        [ 0 ];
     }
     */
    void
    CRTPProfile::create_pt_2_seq_id(data_t &output)
    {
		IncreasePacketCount(PT_2_SEQ_ID);
        RASSERT(IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour);
		
		uint8_t buf[3];
		uint8_t msnLSB = msn & 0x7f; // 7 bit msn
		buf[0] = 0xc0 | (msnLSB >> 4);
		uint8_t ip_id_lsb = IpIdOffset() & 0x1f; // 5 bit ip id offset
		buf[1] = (msnLSB << 4) | (ip_id_lsb >> 1);
		buf[2] = ip_id_lsb << 7;
		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));
		buf[2] |= crc7;
		output.insert(output.end(), buf, buf + sizeof(buf));
    }
    
    /*
     // UOR-2-ID-ext1 replacement (both TS and IP-ID)
     COMPRESSED pt_2_seq_both {
         ENFORCE(ts_stride.UVALUE != 0);
         ENFORCE((ip_id_behavior_innermost.UVALUE ==
             IP_ID_BEHAVIOR_SEQUENTIAL) ||
             (ip_id_behavior_innermost.UVALUE ==
             IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
         discriminator =:= ’11001’                                  [ 5 ];
         msn =:= msn_lsb(7)                                         [ 7 ];
         ip_id =:= ip_id_lsb(ip_id_behavior_innermost.UVALUE, 5)    [ 5 ];
         header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)             [ 7 ];
         ts_scaled =:= scaled_ts_lsb(time_stride.UVALUE, 7)         [ 7 ];
         marker =:= irregular(1)                                    [ 1 ];
     }
     */
    void
    CRTPProfile::create_pt_2_seq_both(uint32_t scaled_timestamp, bool marker, data_t &output)
    {
		IncreasePacketCount(PT_2_SEQ_BOTH);

        RASSERT(IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour);
		uint8_t buf[4];

		uint8_t msnLSB = msn & 0x7f;

		buf[0] = 0xc8 | (msnLSB >> 4);
		
		uint8_t ipLSB = IpIdOffset() & 0x1f;
		buf[1] = (msn << 4) | (ipLSB >> 1);
		buf[2] = ipLSB << 7;
		buf[3] = scaled_timestamp << 1;
		if(marker)
			buf[3] |= 1;

		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));
		buf[2] |= crc7;
		output.insert(output.end(), buf, buf + sizeof(buf));
    }
    
    /*
     // UOR-2-TS replacement
     COMPRESSED pt_2_seq_ts {
     ENFORCE(ts_stride.UVALUE != 0);
     ENFORCE((ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_SEQUENTIAL) ||
			 (ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED));
     discriminator =:= ’1101’										[ 4 ];
     msn =:= msn_lsb(7)												[ 7 ];
     ts_scaled =:= scaled_ts_lsb(time_stride.UVALUE, 5)				[ 5 ];
     marker =:= irregular(1)										[ 1 ];
     header_crc =:= crc7(THIS.UVALUE, THIS.ULENGTH)					[ 7 ];
     ip_id =:= inferred_sequential_ip_id							[ 0 ];
     }
     */
    void
    CRTPProfile::create_pt_2_seq_ts(uint32_t scaled_timestamp, bool marker, data_t &output)
    {
		IncreasePacketCount(PT_2_SEQ_TS);
        // TODO check ts_stride != 0
        RASSERT(IP_ID_BEHAVIOUR_SEQUENTIAL == ip_id_behaviour ||
                IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED == ip_id_behaviour);
        
		uint8_t buf[3];

		uint8_t msn_lsb = msn & 0x7f;

		buf[0] = 0xd0 | (msn_lsb >> 3);
		buf[1] = (msn_lsb & 0x07) << 5;

		uint8_t scaled_ts_lsb = scaled_timestamp & 0x1f;
		buf[1] |= scaled_ts_lsb;

		if (marker)
			buf[2] = 0x80;
		else
			buf[2] = 0x00;

		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));
		buf[2] |= crc7;
		output.insert(output.end(), buf, buf + sizeof(buf));
    }
    
	void
	CRTPProfile::create_profile_1_7_flags1_enc(bool flags1_indicator, const iphdr* ip, data_t& output)
	{
		if (flags1_indicator)
		{
			uint8_t flags = 0;

			if (TTLChanged(ip))
			{
				flags |= 0x40;
			}

			if (TOSChanged(ip))
			{
				flags |= 0x20;
			}
			if (HasDontFragment(ip))
			{
				flags |= 0x10;
			}

			flags |= (static_cast<uint8_t>(ip_id_behaviour) & 0x03) << 2;
			flags |= (static_cast<uint8_t>(reorder_ratio) & 0x03);

			output.push_back(flags);
		}
	}


	/*

	profile_1_flags2_enc(flag)
	{
		UNCOMPRESSED {
			list_indicator [ 1 ];
			pt_indicator [ 1 ];
			time_stride_indicator [ 1 ];
			pad_bit [ 1 ];
			extension [ 1 ];
		}
		COMPRESSED not_present{
			ENFORCE(flag == 0);
			ENFORCE(list_indicator.UVALUE == 0);
			Pelletier & Sandlund Standards Track [Page 75]
			RFC 5225 ROHCv2 Profiles April 2008
			ENFORCE(pt_indicator.UVALUE == 0);
			ENFORCE(time_stride_indicator.UVALUE == 0);
			pad_bit =:= static;
			extension =:= static;
		}
		COMPRESSED present {
			ENFORCE(flag == 1);
			list_indicator =:= irregular(1) [ 1 ];
			pt_indicator =:= irregular(1) [ 1 ];
			time_stride_indicator =:= irregular(1) [ 1 ];
			pad_bit =:= irregular(1) [ 1 ];
			extension =:= irregular(1) [ 1 ];
			reserved =:= compressed_value(3, 0) [ 3 ];
		}
	}
	*/
	void 
	CRTPProfile::create_profile_1_flags2_enc(bool flags2_indicator, const rtphdr* rtp, data_t& output)
	{
		(void)output;
		if (flags2_indicator)
		{
			uint8_t flags = 0;

			/*
			if (rtp->csrc_count > 0)
			{
				flags |= 0x80;
			}
			*/

			if (PTChanged(rtp))
			{
				flags |= 0x40;
			}

			// next flag, 0x20 is time_stride_indicator, not supported

			if (rtp->padding)
			{
				flags |= 0x10;
			}

			if (rtp->extension)
			{
				flags |= 0x80;
			}
		}
	}

	void
	CRTPProfile::create_sdvl_sn_lsb(data_t& output) const
	{
		unsigned int width = msnWindow.width(msn);

		if (width <= 7)
		{
			output.push_back(static_cast<uint8_t>(msn) & 0x7f);
		}
		else if (width <= 14)
		{
			uint8_t msb = static_cast<uint8_t>(msn >> 8) & 0x3f;
			uint8_t lsb = static_cast<uint8_t>(msn);
			output.push_back(0x80 | msb);
			output.push_back(lsb);
		}
		else if (width <= 21)
		{
			output.push_back(0xc0);
			uint8_t msb = static_cast<uint8_t>(msn >> 8);
			uint8_t lsb = static_cast<uint8_t>(msn);
			output.push_back(msb);
			output.push_back(lsb);
		}
	}

	void
	CRTPProfile::UpdateRtpInformation(const rtphdr* rtp)
	{
		memcpy(&last_rtp, rtp, sizeof(last_rtp));
		uint32_t host_ts = rohc_htonl(rtp->timestamp);
		last_scaled_timestamp = host_ts / ts_stride;
		last_ts_offset = host_ts % ts_stride;
		timestamp_window.add(msn, last_scaled_timestamp);
	}

	void
    CRTPProfile::AdvanceState(bool calledFromFeedback, bool ack)
    {
        if (IR_State == state)
        {
            // If we received
            if (calledFromFeedback && ack)
            {
                state = FO_State;
            }
            else if (numberOfIRPacketsSinceReset >= compressor->NumberOfIRPacketsToSend())
                state = FO_State;
        }
        else if (FO_State == state)
        {
            if (calledFromFeedback && ack)
            {
                state = SO_State;
            }
            else if (numberOfFOPacketsSinceReset >= compressor->NumberOfFOPacketsToSend())
                state = SO_State;
            
        }
        else if (SO_State == state)
        {
            
        }
    }

	uint32_t
	CRTPProfile::CalculateTSStride(const rtphdr* rtp) const
	{
		// If we are trying the same packet, return 0
		if (rtp->sequence_number == last_rtp.sequence_number)
			return 0;

		uint16_t sn_diff = rohc_htons(rtp->sequence_number) - rohc_htons(last_rtp.sequence_number);
		uint32_t ts_diff = rohc_htonl(rtp->timestamp) - rohc_htonl(last_rtp.timestamp);
		return ts_diff / sn_diff;
	}

	void 
	CRTPProfile::create_variable_unscaled_timestamp(bool tss_indicator, bool tsc_indicator, const rtphdr* rtp, data_t& baseheader)
	{
		(void)tss_indicator;
		if (!tsc_indicator)
		{
			baseheader.push_back(0xff);
			AppendDataToNBO(baseheader, rtp->timestamp);
		}
	}

	void
	CRTPProfile::MsnWasAcked(uint16_t ackMSN)
	{
		timestamp_window.ackMSN(ackMSN);
		AdvanceState(true, true);
	}

	void CRTPProfile::NackMsn(uint16_t msn) {
		AckFBMsn(msn);
		numberOfIRPacketsSinceReset = numberOfFOPacketsSinceReset = 0;
		state = IR_State;
	}

	void CRTPProfile::StaticNackMsn(uint16_t msn) {
		NackMsn(msn);
	}
}
