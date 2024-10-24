/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define REGISTER_BIT_WIDTH 16 
#define REGISTER_REMAIN_BIT_WIDTH 16 // 32 - BIT_WIDTH
#define REGISTER_WIDTH 65536 // 2 ^ BIT_WIDTH = WATERFALL_WIDTH


struct metadata_t {
  bit<REGISTER_BIT_WIDTH> idx;
  bit<REGISTER_REMAIN_BIT_WIDTH> remain;
  bit<REGISTER_REMAIN_BIT_WIDTH> out_remain;
  bit<32> hash1;
  bool found;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
                    out ingress_intrinsic_metadata_t ig_intr_md) {

  TofinoIngressParser() tofino_parser;
  state start {
    tofino_parser.apply(pkt, ig_intr_md);
    transition parse_ethernet;
  }

  state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
    ETHERTYPE_IPV4:
      parse_ipv4;
    default:
      reject;
    }
  }

  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
    IP_PROTOCOLS_UDP:
      parse_udp;
    IP_PROTOCOLS_TCP:
      parse_tcp;
    default:
      accept;
    }
  }

  state parse_tcp {
    pkt.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    pkt.extract(hdr.udp);
    transition accept;
  }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser( packet_out pkt, inout header_t hdr, in metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

  apply {
    pkt.emit(hdr);
  }
}

control SwitchIngress(inout header_t hdr, inout metadata_t ig_md,
              in ingress_intrinsic_metadata_t ig_intr_md,
              in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
              inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
              inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

  Register<bit<REGISTER_REMAIN_BIT_WIDTH>, bit<REGISTER_BIT_WIDTH>>(REGISTER_WIDTH, 0) table_1; 

  CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                         true,          // reversed
                         false,         // use msb?
                         false,         // extended?
                         32w0xFFFFFFFF, // initial shift register value
                         32w0xFFFFFFFF  // result xor
                         ) CRC32_1;
  Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32_1) hash1;

  RegisterAction<bit<REGISTER_REMAIN_BIT_WIDTH>, bit<REGISTER_BIT_WIDTH>, bool>(table_1) table_1_lookup = {
    void apply(inout bit<REGISTER_REMAIN_BIT_WIDTH> val, out bool read_value) {
      if (ig_md.remain == val) {
        read_value = true;
      } else {
        read_value = false;
      }
    }
  };


  RegisterAction<bit<REGISTER_REMAIN_BIT_WIDTH>, bit<REGISTER_BIT_WIDTH>, bit<REGISTER_REMAIN_BIT_WIDTH>>(table_1) table_1_swap = {
    void apply(inout bit<REGISTER_REMAIN_BIT_WIDTH> val, out bit<REGISTER_REMAIN_BIT_WIDTH> read_value) {
      read_value = val;
      val = ig_md.remain;
    }
  };

  action get_hash1(bit<32> src_addr) {
    bit<32> hash_val = hash1.get({src_addr});
    ig_md.idx = hash_val[REGISTER_BIT_WIDTH - 1:0];
    ig_md.remain = hash_val[31:REGISTER_BIT_WIDTH];
  }

  apply { 
    get_hash1(hdr.ipv4.src_addr);
    bool found_t_1 = table_1_lookup.execute(ig_md.idx); 

    if (found_t_1) {
      ig_md.found = true;
    } else {
      ig_md.found = false;
    }
    ig_md.out_remain = table_1_swap.execute(ig_md.idx);
    ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    ig_intr_dprsr_md.drop_ctl = 0x0;
    ig_intr_tm_md.bypass_egress = 1w1;
  }
}

Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) pipe;

Switch(pipe) main;
