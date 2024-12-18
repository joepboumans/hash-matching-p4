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

        # Get tables
        self.table_1 = self.bfrt_info.table_get("table_1")

        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        logger.info("Finished setup")

    def runTest(self):
        logger.info("Start testing")
        ig_port = swports[0]
        target = self.target

        table_1 = self.table_1

        num_entries = 1
        seed = 1001
        ip_list = self.generate_random_ip_list(num_entries, seed)
        ''' TC:1 Setting up port_metadata and resub'''
        logger.info("Populating resub table...")
        logger.debug(f"\tresub - inserting table entry with port {ig_port}")

        ip_entry = ip_list[0]
        src_addr = "1.2.3.4"
        dst_addr = "5.6.7.8"
        src_port = "1234"
        dst_port = "88"
        protocol = "6"

        pkt_in = testutils.simple_tcp_packet(ip_src=src_addr, ip_dst=dst_addr, tcp_sport=int(src_port), tcp_dport=int(dst_port))
        logger.info(pkt_in)
        ip_hash = crc32(src_addr, dst_addr, src_port, dst_port, protocol, 0xFFFFFFFF)
        # Should equal | remain | idx |
        logger.info(ip_hash.to_bytes(4, byteorder='big').hex())
        ig_port = swports[2]
        testutils.send_packet(self, ig_port, pkt_in)
        testutils.verify_packet(self, pkt_in, ig_port)
        return

    def tearDown(self):
        logger.info("Tearing down test")

        self.table_1.entry_del(self.target)
