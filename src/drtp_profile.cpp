#include <rohc/rohc.h>
#include "drtp_profile.h"
#include "dudp_profile.h"
#include <rohc/log.h>

using namespace std;


namespace ROHC
{
    DRTPProfile::DRTPProfile(Decompressor* decomp, uint16_t cid)
    : DProfile(decomp, cid)
    ,ts_stride(TS_STRIDE_DEFAULT)
    ,time_stride(TIME_STRIDE_DEFAULT)
    , udp()
    , rtp()
    {
    }
    
    bool
    DRTPProfile::ParseIR(global_control& gc, const data_t& data, const_data_iterator& pos)
    {
        const_data_iterator end(data.end());
        if (!DProfile::parse_ipv4_static(gc, pos, end))
            return false;
        
        if(!DUDPProfile::parse_udp_static(gc, pos, end))
            return false;
        
        if(!parse_rtp_static(gc, pos, end))
            return false;
        
        if(!DProfile::parse_ipv4_regular_innermost_dynamic(gc, pos, end)) {
            return false;
        }

        if(!parse_udp_regular_dynamic(gc, pos, end))
            return false;
        
        return parse_rtp_dynamic(gc, pos, end);
    }
    
    void
    DRTPProfile::ParseCO(uint8_t packetTypeIndication, data_t &data, data_iterator pos, data_t &output)
    {
        // pos will point at remainder of base header
        // Make first octet of base header adjacent to the remainder
        --pos;
        *pos = packetTypeIndication;
        
        if (0xfa == packetTypeIndication)
        {
			//cout << "parse_co_common" << endl;
            if(!parse_co_common(pos, data.end()))
                return;
            
        }
        else if (0x80 == (packetTypeIndication & 0xf0))
        {
            if(!parse_pt_0_crc7(pos, data.end()))
                return;
        }
        else if (0 == (packetTypeIndication & 0x80))
        {
            if(!parse_pt_0_crc3(pos, data.end())) {
                return;
            }
        }
		else if ((0xa0 == (packetTypeIndication & 0xe0)) &&
			(ip_id_behaviour >= IP_ID_BEHAVIOUR_RANDOM))
		{
            if(!parse_pt_1_rnd(pos, data.end()))
                return;
		}
        else if( (0x90 == (packetTypeIndication & 0xf0)) &&
			(ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED))
        {
            if(!parse_pt_1_seq_id(pos, data.end())) {
                return;
            }
        }
		else if ( (0xa0 == (packetTypeIndication & 0xe0)) &&
			(ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED))
		{
			if(!parse_pt_1_seq_ts(pos, data.end())) {
                return;
            }
		}
		else if ( (0xc0 == (packetTypeIndication & 0xe0)) &&
			(ip_id_behaviour >= IP_ID_BEHAVIOUR_RANDOM))
		{
            if (!parse_pt_2_rnd(pos, data.end())) {
                return;
            }
		}
        else if ((0xc0 == (packetTypeIndication & 0xf8)) &&
			(ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED))
        {
            if(!parse_pt_2_seq_id(pos, data.end())) {
                return;
            }
        }
		else if ((0xc8 == (packetTypeIndication & 0xf8)) &&
			(ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED))
		{
			if(!parse_pt_2_seq_both(pos, data.end())) {
                return;
            }
		}
		else if ((0xd0 == (packetTypeIndication & 0xf0)) &&
			(ip_id_behaviour <= IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED))
		{
            if(!parse_pt_2_seq_ts(pos, data.end()))
                return;
		}
        else
        {
            error("Unknown base header type: %x\n", (unsigned) packetTypeIndication);
            SendNack();
            return;
        }

        if (data.end() == pos)
        {
            error("RTP - ParseCO, missing data");
            SendNack();
            return;
        }

		if(!parse_ipv4_innermost_irregular(pos, data.end()))
            return;
        
        // udp irreg
        if (udp_checksum_used)
        {
            if (!GetValue(pos, data.end(), udp.check)) {
                error("RTP - failed to get udp checksum\n");
                return;
            }
        }
        
		// The sequence number should always be the msn, in NB order
		rtp.sequence_number = rohc_htons(msn);

        // Append payload
        size_t ipIdx = output.size();
        AppendData(output, ip);
        AppendData(output, udp);
		AppendData(output, rtp);
        output.insert(output.end(), pos, data.end());
        iphdr* pip = reinterpret_cast<iphdr*>(&output[ipIdx]);
        pip->tot_len = rohc_htons(static_cast<uint16_t>(output.size()));
        udphdr* pudp = reinterpret_cast<udphdr*>(pip+1);
        pudp->len = rohc_htons(static_cast<uint16_t>(output.size() - sizeof(iphdr)));
        calculateIpHeaderCheckSum(pip);
        SendFeedback1();        
    }
    
    void
    DRTPProfile::ParseCORepair(const data_t& /*data*/, const_data_iterator /*r2_crc3_pos*/, data_t& /*output*/)
    {
        
    }
    
    void
    DRTPProfile::MergeGlobalControlAndAppendHeaders(const ROHC::global_control &gc, data_t &output)
    {
        ++numberofIRPackets;
        ++numberOfPacketsReceived;
        
        msn = gc.msn;
        SetReorderRatio(gc.reorder_ratio);
        ip_id_behaviour = gc.ip_id_behaviour;
        udp_checksum_used = gc.udp_checksum_used;
        ip = gc.ip;
        udp = gc.udp;
        rtp = gc.rtp;

		if (gc.ts_stride)
			ts_stride = gc.ts_stride;

		UpdateIPIDOffsetFromID();

		if (ts_stride)
		{
			ts_offset = rohc_htonl(rtp.timestamp) * ts_stride;
		}
        
        AppendData(output, ip);
        AppendData(output, udp);        
        AppendData(output, rtp);  

		SendFeedback1();
    }
    
    bool
    DRTPProfile::parse_rtp_static(ROHC::global_control &gc, const_data_iterator& pos, const_data_iterator end)
    {
        gc.rtp.version = 2;

        if(!GetValue(pos, end, gc.rtp.ssrc)) {
            error("parse_rtp_static, not enough data\n");
            return false;
        }
        return true;
    }
    
    /*
     COMPRESSED rtp_dynamic {
     reserved =:= compressed_value(1, 0) [ 1 ];
     reorder_ratio =:= irregular(2) [ 2 ];
     list_present =:= irregular(1) [ 1 ];
     tss_indicator =:= irregular(1) [ 1 ];
     tis_indicator =:= irregular(1) [ 1 ];
     pad_bit =:= irregular(1) [ 1 ];
     extension =:= irregular(1) [ 1 ];
     
     marker =:= irregular(1) [ 1 ];
     payload_type =:= irregular(7) [ 7 ];
     
     sequence_number =:= irregular(16) [ 16 ];
     timestamp =:= irregular(32) [ 32 ];
     ts_stride =:= sdvl_or_default(tss_indicator.CVALUE,
     TS_STRIDE_DEFAULT) [ VARIABLE ];
     time_stride =:= sdvl_or_default(tis_indicator.CVALUE,
     TIME_STRIDE_DEFAULT) [ VARIABLE ];
     csrc_list =:= csrc_list_dynchain(list_present.CVALUE,
     cc.UVALUE) [ VARIABLE ];
     }
    */
    bool
    DRTPProfile::parse_rtp_dynamic(ROHC::global_control &gc, const_data_iterator& pos, const_data_iterator end) {
        if ((end - pos) < 1) {
            error("parse_rtp_dynamic, not enough data\n");
            return false;
        }
        uint8_t res_RRatio_LP_Tss_Tis_Pad_Ext = *pos++;
        if (0 != (res_RRatio_LP_Tss_Tis_Pad_Ext & 0x80)) {
            error("DRTPProfile::parse_rtp_dynamic, reserved not zero\n");
            return false;
        }
        
        gc.reorder_ratio = static_cast<Reordering_t>(res_RRatio_LP_Tss_Tis_Pad_Ext >> 5);
        
        bool list_present = (res_RRatio_LP_Tss_Tis_Pad_Ext & 0x10) > 0;
        bool tss_indicator = (res_RRatio_LP_Tss_Tis_Pad_Ext & 0x08) > 0;
        bool tis_indicator = (res_RRatio_LP_Tss_Tis_Pad_Ext & 0x04) > 0;
        
        gc.rtp.padding = (res_RRatio_LP_Tss_Tis_Pad_Ext >> 1) & 1;
        gc.rtp.extension = res_RRatio_LP_Tss_Tis_Pad_Ext & 1;
        
        uint8_t marker_payload_type = *pos++;
        gc.rtp.marker = marker_payload_type >> 7;
        gc.rtp.payload_type = marker_payload_type & 0x7f;
        
        if(!GetValue(pos, end, gc.rtp.sequence_number)) {
            error("parse_rtp_dynamic, failed to get seq num\n");
            return false;
        }
        gc.msn = rohc_htons(gc.rtp.sequence_number);
        if(!GetValue(pos, end, gc.rtp.timestamp)) {
            error("parse_rtp_dynamic, failed to get timestamp\n");
            return false;
        }
        if (tss_indicator)
        {
            if(!SDVLDecode(pos, end, &gc.ts_stride)) {
                error("parse_rtp_dynamic, failed to get TS_STRIDE\n");
                return false;
            }
        }
        
        if (tis_indicator)
        {
            if(!SDVLDecode(pos, end, &gc.time_stride)) {
                error("parse_rtp_dynamic, failed to get TIME_STRIDE\n");
                return false;
            }
        }
        
        if (list_present) {
            // TODO parse csrc list
        }
        else
        {
            gc.rtp.csrc_count = 0;
        }
        return true;
    }

    bool
    DRTPProfile::parse_udp_regular_dynamic(ROHC::global_control &gc, const_data_iterator& pos, const_data_iterator end) {
        if (!GetValue(pos, end, gc.udp.check)) {
            error("parse_udp_regular_dynamic, failed to get udp checksum\n");
            return false;
        }
        gc.udp_checksum_used = gc.udp.check != 0;
        return true;
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
	bool
	DRTPProfile::parse_co_common(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 3) {
            error("parse_co_common, not enough data\n");
            return false;
        }
		data_iterator headerStart = pos;

		// skip packet type indication
		++pos;

		uint8_t marker_crc7 = *pos;
		// reset CRC
		*pos++ &= 0x80;

		uint8_t flags_crc3 = *pos++;

		bool flags1_indicator = (flags_crc3 & 0x80) > 0;
		bool flags2_indicator = (flags_crc3 & 0x40) > 0;
		bool tsc_indicator = (flags_crc3 & 0x20) > 0;
		bool tss_indicator = (flags_crc3 & 0x10) > 0;
		bool ip_id_indicator = (flags_crc3 & 0x08) > 0;

		bool ttl_hopl_indicator = false;
		bool tos_tc_indicator = false;
		bool df = HasDontFragment(&ip);
		IPIDBehaviour_t new_ip_id_behaviour = ip_id_behaviour;
		Reordering_t newRR = GetReorderRatio();;

        if (!parse_profile_1_7_flags1_enc(flags1_indicator, pos, end, ttl_hopl_indicator, tos_tc_indicator, df, new_ip_id_behaviour, newRR)){
            return false;
        }

		bool list_indicator = false;
		bool pt_indicator = false;
		bool tis_indicator = false;
		bool pad_bit = rtp.padding != 0;
		bool extension = rtp.extension != 0;

		if (!parse_profile_1_flags2_enc(flags2_indicator, pos, end, list_indicator, pt_indicator, tis_indicator, pad_bit, extension)) {
            return false;
        }

		uint8_t tos_tc = ip.tos;
		if (tos_tc_indicator)
		{
            if ((end - pos) < 1) {
                error("parse_co_common, tos_tc_indicator\n");
                return false;
            }
			tos_tc = *pos++;
		}

		uint8_t ttl_hopl = ip.ttl;
		if (ttl_hopl_indicator)
		{
            if ((end - pos) < 1) {
                error("parse_co_common, ttl_hopl_indicator\n");
                return false;
            }
			ttl_hopl = *pos++;
		}

		uint8_t new_payload_type = rtp.payload_type;
		if (pt_indicator)
		{
            if ((end - pos) < 1) {
                error("parse_co_common, pt_indicator\n");
                return false;
            }
			new_payload_type = *pos++;
		}

		uint16_t new_msn = 0;
		unsigned int delta_msn = 0;
        if (!parse_sdvl_sn_lsb(pos, end, new_msn, delta_msn)) {
            return false;
        }
		
		uint16_t new_ip_id_offset = ip_id_offset;
		uint16_t new_ip_id;
        if (!parse_ip_id_sequential_variable(ip_id_indicator, pos, end, new_ip_id_offset, new_ip_id)) {
            return false;
        }


		// ts_scaled
		// timestamp
		// ts_stride
		uint32_t new_timestamp = 0;
		if (!parse_variable_unscaled_timestamp(tss_indicator, tsc_indicator, pos, end, new_timestamp) ) {
            return false;
        }
            

		uint32_t new_ts_stride = ts_stride;
		if (tss_indicator) {
            if (!SDVLDecode(pos, end, &new_ts_stride)) {
                error("parse_co_common, tss_indicator\n");
                SendNack();
                return false;
            }
		}

		// time_stride
		uint32_t new_time_stride = time_stride;

		// csrc_list

		// Check CRC7 && CRC3
		if ((flags_crc3 & 7) != control_crc3(newRR, new_ts_stride, new_time_stride)) {
            //error("parse_co_common, CRC 3\n");
			SendNack();
			return false;
		}

		uint8_t calc_crc7 = CRC7(headerStart, pos);
		if (calc_crc7 != (marker_crc7 & 0x7f)) {
            error("parse_co_common, CRC 7\n");
			SendNack();
			return false;
		}

		if (df) {
			SetDontFragment(&ip);
		}
		else {
			ClearDontFragment(&ip);
		}

		ip.tos = tos_tc;
		ip.ttl = ttl_hopl;

		ip_id_behaviour = new_ip_id_behaviour;
		SetReorderRatio(newRR);

        rtp.marker = !!(marker_crc7 & 0x80);
		rtp.padding = pad_bit;
		rtp.extension = extension;
		rtp.payload_type = new_payload_type;

		msn = new_msn;

		if (ip_id_indicator) {
			ip.id = new_ip_id;
			UpdateIPIDOffsetFromID();
		}
		else {
			ip_id_offset = new_ip_id_offset;
			UpdateIPIDFromOffset();
		}

		if (tss_indicator) {
			ts_stride = new_ts_stride;
		}

		if (!tsc_indicator) {
			rtp.timestamp = new_timestamp;
			if (ts_stride) {
				uint32_t host_ts = rohc_htonl(new_timestamp);
				ts_scaled = host_ts / ts_stride;
				ts_offset = host_ts % ts_stride;
			}
		}
		else {
			return parse_inferred_scaled_ts(delta_msn);
		}

		return true;
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
	bool 
	DRTPProfile::parse_pt_0_crc3(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 1) {
            error("parse_pt_0_crc3, not enough data\n");
            return false;
        }
		uint8_t msn_crc3 = *pos++;

		uint8_t cpy = msn_crc3 & 0xf8;

		uint8_t crc3 = CRC3(&cpy, &cpy + 1);
		if ((msn_crc3 & 0x07) != crc3) {
            error("parse_pt_0_crc3, checksum\n");
			SendNack();
			return false;
		}

		uint16_t lsbMsn = (msn_crc3 >> 3) & 0x0f;
		uint16_t delta_msn = UpdateMSN(lsbMsn, 4, msn);
		
		if (!parse_inferred_scaled_ts(delta_msn)) {
            return false;
        }
		parse_inferred_sequential_ip_id(delta_msn);

		return true;
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
	bool 
	DRTPProfile::parse_pt_0_crc7(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 2) {
            error("parse_pt_0_crc7, not enough data\n");
            return false;
        }
		uint8_t buf[2];
		buf[0] = *pos++;
		buf[1] = *pos++;

		uint8_t crc7 = buf[1] & 0x7f;
		buf[1] &= 0x80;

		if (crc7 != CRC7(buf, buf + sizeof(buf))) {
            error("parse_pt_0_crc7, checksum\n");
			SendNack();
			return false;
		}
		uint16_t lsbMsn = ((buf[0] & 0x0f) << 1) | (buf[1] >> 7);
		uint16_t delta_msn = UpdateMSN(lsbMsn, 5, msn);

		if (!parse_inferred_scaled_ts(delta_msn)) {
            return false;
        }

		parse_inferred_sequential_ip_id(delta_msn);

		return true;
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
	bool 
	DRTPProfile::parse_pt_1_rnd(data_iterator& pos, const data_iterator& end)
	{
        if ((end - pos) < 2) {
            error("parse_pt_1_rnd, not enough data\n");
            return false;
        }
		uint8_t buf[2];
		buf[0] = *pos++;
		buf[1] = *pos++;

		uint8_t ts_scaled_crc3 = buf[1];
		buf[1] &= 0xf8;

		uint8_t crc3 = CRC3(buf, buf + sizeof(buf));

		if (crc3 != (ts_scaled_crc3 & 0x07)) {
            error("parse_pt_1_rnd, checksum\n");
			SendNack();
			return false;
		}

		rtp.marker = (buf[0] & 0x10) > 0;

		uint8_t lsbMsn = buf[0] & 0x0f;

		uint8_t scaled_ts_lsb = ts_scaled_crc3 >> 3;

		UpdateMSN(lsbMsn, 4, msn);
		UpdateTimestamp(scaled_ts_lsb, 5);

		return true;
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
	bool 
	DRTPProfile::parse_pt_1_seq_id(data_iterator& pos, const data_iterator& end)
	{
        if ((end - pos) < 2) {
            error("parse_pt_1_seq_id, not enough data\n");
            return false;
        }
		uint8_t buf[2];
		buf[0] = *pos++;
		buf[1] = *pos++;

		uint8_t msn_crc3 = buf[1];
		buf[1] &= 0xf8;

		uint8_t crc3 = CRC3(buf, buf + sizeof(buf));
		if ((msn_crc3 & 7) != crc3) {
            error("parse_pt_1_seq_id, checksum\n");
			SendNack();
			return false;
		}

		uint16_t lsbMsn = msn_crc3 >> 3;
		uint16_t delta_msn = UpdateMSN(lsbMsn, 5, msn);
        UpdateIPIDOffset(buf[0] & 0x0f, 4, ip_id_offset);
        UpdateIPIDFromOffset();

		return parse_inferred_scaled_ts(delta_msn);
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
	bool 
	DRTPProfile::parse_pt_1_seq_ts(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 2) {
            error("parse_pt_1_seq_ts, not enough data\n");
            return false;
        }
		uint8_t buf[2];
		buf[0] = *pos++;
		buf[1] = *pos++;

		uint8_t scaled_ts_lsb_crc3 = buf[1];
		buf[1] &= 0xf8;

		uint8_t crc3 = CRC3(buf, buf + sizeof(buf));
		if (crc3 != (scaled_ts_lsb_crc3 & 0x07))
		{
            error("parse_pt_1_seq_ts, checksum\n");
			SendNack();
			return false;
		}

		rtp.marker = buf[0] & 0x10;

		return true;
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
	bool 
	DRTPProfile::parse_pt_2_rnd(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 3) {
            error("parse_pt_2_rnd, not enough data\n");
            return false;
        }
		uint8_t buf[3];
		buf[0] = *pos++;
		buf[1] = *pos++;
		buf[2] = *pos++;

		uint8_t marker_crc7 = buf[2];
		buf[2] &= 0x80;

		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));

		if (crc7 != (marker_crc7 & 0x7f)) {
            error("parse_pt_2_rnd, checksum\n");
			SendNack();
			return false;
		}

		uint8_t lsbMsn = (buf[0] & 0x1f) << 2;
		lsbMsn |= buf[1] >> 6;

		uint8_t scaled_ts_lsb = buf[1] & 0x3f;

		rtp.marker = (marker_crc7 & 0x80) > 0;

		UpdateMSN(lsbMsn, 7, msn);
		UpdateTimestamp(scaled_ts_lsb, 6);

		return true;
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
	bool 
	DRTPProfile::parse_pt_2_seq_id(data_iterator& pos, const data_iterator& end)
	{
        if ((end - pos) < 3) {
            error("parse_pt_2_seq_id, not enough data\n");
            return false;
        }
		uint8_t buf[3];

		buf[0] = *pos++;
		buf[1] = *pos++;
		buf[2] = *pos++;

		uint8_t ip_id_crc7 = buf[2];
		buf[2] &= 0x80;

		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));

		if (crc7 != (ip_id_crc7 & 0x7f)) {
            error("parse_pt_2_seq_id, checksum\n");
			SendNack();
			return false;
		}

		uint8_t lsbMsn = (buf[0] & 0x07) << 4;
		lsbMsn |= buf[1] >> 4;
		uint8_t lsbIpId = (buf[1] & 0x0f) << 1;
		lsbIpId |= ip_id_crc7 >> 7;

		uint16_t delta_msn = UpdateMSN(lsbMsn, 7, msn);
		UpdateIPIDOffset(lsbIpId, 5, ip_id_offset);
		UpdateIPIDFromOffset();
		return parse_inferred_scaled_ts(delta_msn);
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
	bool 
	DRTPProfile::parse_pt_2_seq_both(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 4) {
            error("parse_pt_2_seq_both, not enough data\n");
            return false;
        }
		uint8_t buf[4];
		buf[0] = *pos++;
		buf[1] = *pos++;
		buf[2] = *pos++;
		buf[3] = *pos++;

		uint8_t ip_id_crc7 = buf[2];
		buf[2] &= 0x80;

		if ((ip_id_crc7 & 0x7f) != CRC7(buf, buf + sizeof(buf))) {
            error("parse_pt_2_seq_both, checksum\n");
			SendNack();
			return false;
		}

		uint16_t lsbMsn = (buf[0] & 0x07) << 4;
		lsbMsn |= buf[1] >> 4;

		uint8_t lsbIpId = (buf[1] & 0x0f) << 1;
		lsbIpId |= ip_id_crc7 >> 7;

		uint8_t scaled_ts_lsb = buf[3] >> 1;
		rtp.marker = (buf[3] & 1) > 0;

		UpdateMSN(lsbMsn, 7, msn);
		UpdateIPIDOffset(lsbIpId, 5, ip_id_offset);
		UpdateIPIDFromOffset();
		UpdateTimestamp(scaled_ts_lsb, 7);

		return true;
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
	bool 
	DRTPProfile::parse_pt_2_seq_ts(data_iterator& pos, const data_iterator& end) {
        if ((end - pos) < 3) {
            error("parse_pt_2_seq_ts, not enough data\n");
            return false;
        }
		uint8_t buf[3];
		buf[0] = *pos++;
		buf[1] = *pos++;
		buf[2] = *pos++;

		uint8_t marker_crc = buf[2];
		buf[2] &= 0x80;

		uint8_t crc7 = CRC7(buf, buf + sizeof(buf));

		if ((marker_crc & 0x7f) != crc7) {
            error("parse_pt_2_seq_ts, checksum\n");
			SendNack();
			return false;
		}

		uint8_t msn_lsb = (buf[0] & 0x0f) << 3;
		msn_lsb |= buf[1] >> 5;

		uint8_t scaled_ts_lsb = buf[1] & 0x1f;

		rtp.marker = marker_crc >> 7;

		uint16_t delta_msn = UpdateMSN(msn_lsb, 7, msn);
		parse_inferred_sequential_ip_id(delta_msn);

		UpdateTimestamp(scaled_ts_lsb, 5);
		return true;
	}


	uint8_t 
	DRTPProfile::control_crc3(Reordering_t new_reorder_ratio, uint32_t new_ts_stride, uint32_t new_time_stride) const {
		data_t data;

		data.push_back(static_cast<uint8_t>(new_reorder_ratio) & 0x03);
		AppendDataToNBO(data, new_ts_stride);
		AppendDataToNBO(data, new_time_stride);
		return CRC3(data.begin(), data.end());
	}
		

	bool 
	DRTPProfile::parse_profile_1_7_flags1_enc(bool flags1_indicator, data_iterator& pos, const data_iterator& end, bool& ttl_hopl_indicator, bool& tos_tc_indicator, bool& df, IPIDBehaviour_t& new_ip_id_behaviour, Reordering_t& new_reorder_ratio) const {
		if (flags1_indicator) {
            if ((end - pos) < 1) {
                error("parse_profile_1_7_flags1_enc, not enough data\n");
                return false;
            }
			uint8_t flags = *pos++;
			ttl_hopl_indicator = (flags & 0x40) > 0;
			tos_tc_indicator = (flags & 0x20) > 0;
			df = (flags & 0x10) > 0;
			new_ip_id_behaviour = static_cast<IPIDBehaviour_t>((flags >> 2) & 3);
			new_reorder_ratio = static_cast<Reordering_t>(flags & 3);
		}

		return true;
	}

	bool 
	DRTPProfile::parse_profile_1_flags2_enc(bool flags2_indicator, data_iterator& pos, const data_iterator& end, bool& list_indicator, bool& pt_indicator, bool& tis_indicator, bool& pad_bit, bool& extension) const {
		if (flags2_indicator) {
            if ((end - pos) < 1) {
                error("parse_profile_1_flags2_enc, not enough data\n");
                return false;
            }
			uint8_t flags = *pos++;
			list_indicator = (flags & 0x80) > 0;
			pt_indicator = (flags & 0x40) > 0;
			tis_indicator = (flags & 0x20) > 0;
			pad_bit = (flags & 0x10) > 0;
			extension = (flags & 0x08) > 0;
		}
		
		return true;
	}

    bool DRTPProfile::parse_sdvl_sn_lsb(data_iterator& pos, const data_iterator& end, uint16_t& new_msn, unsigned int& delta_msn) const
	{
        if ((end - pos) < 1) {
            error("parse_sdvl_sn_lsb, not enough data\n");
            return false;
        }
		uint8_t first = *pos++;

		if ((first & 0xe0) == 0xc0) {
            if ((end - pos) < 2) {
                error("parse_sdvl_sn_lsb, not enough data\n");
                return false;
            }
			uint8_t msb = *pos++;
			uint8_t lsb = *pos++;
			new_msn = (msb << 8) + lsb;
			delta_msn = new_msn - msn;
		}
		else if ((first & 0xc0) == 0x80) {
            if ((end - pos) < 1) {
                error("parse_sdvl_sn_lsb, not enough data\n");
                return false;
            }
			uint8_t msb = first & 0x3f;
			uint8_t lsb = *pos++;
			uint16_t maskedMsn = (msb << 8) + lsb;
			delta_msn = UpdateMSN(maskedMsn, 14, new_msn);
		}
		else if ((first & 0x80) == 0x00) {
			uint16_t maskedMsn = first & 0x7f;
			delta_msn = UpdateMSN(maskedMsn, 7, new_msn);
		}
		else {
            error("parse_sdvl_sn_lsb, unknown\n");
            return false;
		}

		return true;
	}

	bool 
	DRTPProfile::parse_variable_unscaled_timestamp(bool /*tss_indicator*/, bool tsc_indicator, data_iterator& pos, const data_iterator& end, uint32_t& new_timestamp) const {
		if (!tsc_indicator) {
            if ((end - pos) < 5) {
                error("parse_variable_unscaled_timestamp, not enough data\n");
                return false;
            }
			uint8_t disc = *pos++;
            if (0xff != disc) {
                error("parse_variable_unscaled_timestamp, wrong disc\n");
                return false;
            }
			new_timestamp = (*pos++) << 24;
			new_timestamp |= (*pos++) << 16;
			new_timestamp |= (*pos++) << 8;
			new_timestamp |= (*pos++);
		}

		return true;
	}

	bool 
	DRTPProfile::parse_inferred_scaled_ts(uint16_t delta_msn) {
        if (!ts_stride) {
//            error("received inferred scaled ts, but have no ts_stride\n");
            SendNack();
            return false;
        }
        
        
		uint32_t new_ts = rohc_htonl(rtp.timestamp) + delta_msn * ts_stride;
		rtp.timestamp = rohc_htonl( new_ts );
		ts_offset = new_ts % ts_stride;
		ts_scaled = new_ts / ts_stride;
        return true;
	}

	void
	DRTPProfile::UpdateTimestamp(uint32_t ts_scaled_lsb, unsigned int width) {
		uint32_t lowerBound = ts_scaled;

		uint32_t mask = (1 << width) - 1;

		uint32_t new_ts_scaled = (ts_scaled & ~mask) | (ts_scaled_lsb & mask);
		if (new_ts_scaled < lowerBound) {
			new_ts_scaled += (1 << width);
		}

		uint32_t new_ts = new_ts_scaled * ts_stride + ts_offset;

//		if (new_ts < rohc_htonl(rtp.timestamp))
			//cout << "new is less" << endl;

		rtp.timestamp = rohc_htonl(new_ts);
		ts_scaled = new_ts_scaled;
	}
}
