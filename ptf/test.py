#!/usr/bin/python3
import logging
from collections import namedtuple
from math import radians
import random

from ptf import config
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
from utils import *
import numpy as np

swports = get_sw_ports()
project_name = 'hash_matching'
logger = logging.getLogger(project_name)

if not len(logger.handlers):
    sh = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s - %(name)s - %(funcName)s]: %(message)s')
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)

class DigestResubmitTest(BfRuntimeTest):
    def setUp(self):
        logger.info("Starting setup")
        client_id = 0
        BfRuntimeTest.setUp(self, client_id)
        logger.info("\tfinished BfRuntimeSetup")
        self.bfrt_info = self.interface.bfrt_info_get(project_name)

        # Get resubmission and port metadata tables
        self.port_meta = self.bfrt_info.table_get("$PORT_METADATA")
        self.resub = self.bfrt_info.table_get("resub")

        # Get digest/learn filter from gRPC
        self.learn_filter = self.bfrt_info.learn_get("digest")
        self.learn_filter.info.data_field_annotation_add("src_addr", "ipv4")
        self.learn_filter.info.data_field_annotation_add("dst_addr", "ipv4")

        # Get Waterfall tables
        self.table_1 = self.bfrt_info.table_get("table_1")
        # self.table_2 = self.bfrt_info.table_get("table_2")
        # self.table_3 = self.bfrt_info.table_get("table_3")
        # self.table_4 = self.bfrt_info.table_get("table_4")

        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        logger.info("Finished setup")

    def runTest(self):
        logger.info("Start testing")
        ig_port = swports[0]
        target = self.target
        port_meta = self.port_meta
        resub = self.resub

        learn_filter = self.learn_filter

        table_1 = self.table_1
        # table_2 = self.table_2
        # table_3 = self.table_3
        # table_4 = self.table_4

        num_entries = 1
        seed = 1001
        ip_list = self.generate_random_ip_list(num_entries, seed)
        ''' TC:1 Setting up port_metadata and resub'''
        logger.info("Populating resub table...")
        logger.debug(f"\tresub - inserting table entry with port {ig_port}")

        key = resub.make_key([gc.KeyTuple('ig_md.found', True)])
        data = resub.make_data([], "SwitchIngress.no_resub")
        key = resub.make_key([gc.KeyTuple('ig_md.found', False)])
        data = resub.make_data([], "SwitchIngress.resubmit_hdr")
        resub.entry_add(target, [key], [data])

        ip_entry = ip_list[0]
        src_addr = "1.2.3.4"
        dst_addr = "5.6.7.8"
        src_port = "1234"
        dst_port = "88"
        protocol = "6"

        pkt_in = testutils.simple_tcp_packet(ip_src=src_addr, ip_dst=dst_addr, tcp_sport=int(src_port), tcp_dport=int(dst_port))
        logger.info(pkt_in)
        ip_hash = crc32(src_addr, dst_addr, src_port, dst_port, protocol, 0xFFFFFFFF)
        logger.info(ip_hash)
        logger.info(ip_hash.to_bytes(4, byteorder='little', signed=False).hex())
        ig_port = swports[2]
        testutils.send_packet(self, ig_port, pkt_in)
        testutils.verify_packet(self, pkt_in, ig_port)
        return
        for ip_entry in ip_list:
            src_addr = getattr(ip_entry, "ip")

            # logger.info("Populating port_meta table...")
            ig_port = swports[2]

            # logger.info("Adding entries to port_meta and resub tables")
            ''' TC:2 Send, receive and verify packets'''
            pkt_in = testutils.simple_tcp_packet(ip_src=src_addr)
            # logger.info("Sending simple packet to switch")
            testutils.send_packet(self, ig_port, pkt_in)
            # logger.info("Verifying simple packet has been correct...")
            testutils.verify_packet(self, pkt_in, ig_port)
            logger.info("..packet received correctly")
            # testutils.send_packet(self, ig_port, pkt_in)
            # testutils.verify_packet(self, pkt_in, ig_port)

        ''' TC:3 Get data from the digest'''
        total_recv = 0
        digest = self.interface.digest_get()
        while(digest != None):
            data_list = learn_filter.make_data_list(digest)
            logger.info(f"Received {len(data_list)} entries from the digest")
            total_recv += len(data_list)
            for data in data_list:
                data_dict = data.to_dict()
                recv_src_addr = data_dict["src_addr"]
                recv_dst_addr = data_dict["dst_addr"]
                recv_src_port = data_dict["src_port"]
                recv_dst_port = data_dict["dst_port"]
                recv_protocol = data_dict["protocol"]
                logger.info(f"{recv_src_addr = } : {recv_dst_addr = } | {recv_src_port = } {recv_dst_port = } | {recv_protocol = }")
            try:
                digest = self.interface.digest_get()
            except:
                break;
        assert(total_recv == num_entries)

        ''' TC:4 Validate received digest data'''
        # # Get data from table_1
        # summed = 0
        # data_table_1 = table_1.entry_get(target, [], {"from_hw" : True})
        # for data, key in data_table_1:
        #     data_dict = data.to_dict()
        #     entry_val = data_dict[f"SwitchIngress.table_1.f1"][0]
        #     summed += entry_val
        #     if entry_val != 0:
        #         logger.info(data_dict)
        #         logger.info(entry_val.to_bytes(2,'big'))
        # logger.info(f"Table1 has {summed} total remainders")
        # assert(summed != 0)
        # #
        # # # Get data from table_2
        # summed = 0
        # data_table_2 = table_2.entry_get(target, [], {"from_hw" : True})
        # for data, key in data_table_2:
        #     data_dict = data.to_dict()
        #     entry_val = data_dict[f"SwitchIngress.table_2.f1"][0]
        #     summed += entry_val
        #     if entry_val != 0:
        #         logger.info(data_dict)
        #         logger.info(entry_val.to_bytes(2,'big'))
        #
        # # # assert(summed != 0)
        # logger.info(f"Table2 has {summed} total remainders")
        #
        # # Get data from table_3
        # summed = 0
        # data_table_3 = table_3.entry_get(target, [], {"from_hw" : True})
        # for data, key in data_table_3:
        #     data_dict = data.to_dict()
        #     entry_val = data_dict[f"SwitchIngress.table_3.f1"][0]
        #     summed += entry_val
        #     if entry_val != 0:
        #         logger.info(data_dict)
        #         logger.info(entry_val.to_bytes(2,'big'))
        #
        # # assert(summed != 0)
        # logger.info(f"Table3 has {summed} total remainders")

        # Get data from table_4
        summed = 0
        data_table_4 = table_4.entry_get(target, [], {"from_hw" : True})
        for data, key in data_table_4:
            data_dict = data.to_dict()
            entry_val = data_dict[f"SwitchIngress.table_4.f1"][0]
            summed += entry_val
            if entry_val != 0:
                logger.info(data_dict)
                logger.info(entry_val.to_bytes(2,'big'))

        # assert(summed != 0)
        logger.info(f"Table4 has {summed} total remainders")
        # data_5998, _ = next(table_4.entry_get(target, [table_4.make_key([gc.KeyTuple("$REGISTER_INDEX", 3411)])]))        
        # logger.info(data_5998)

    def tearDown(self):
        logger.info("Tearing down test")
        self.resub.entry_del(self.target)
        self.port_meta.entry_del(self.target)

        self.table_1.entry_del(self.target)
        # self.table_2.entry_del(self.target)
        # self.table_3.entry_del(self.target)
        # self.table_4.entry_del(self.target)