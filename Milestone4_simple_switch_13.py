# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import vlan

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def add_flow_send(self,in_port, out_port, msg, match=None, actions=None):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # If there is a match rule, install it
        if match is not None:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # Buffered, install rule and return
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                # Unbuffered, install rule and send packet
                self.add_flow(datapath, 1, match, actions)
        # Send packet
        data=None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        vlan_header = pkt.get_protocols(vlan.vlan)

        if eth.ethertype == ether_types.ETH_TYPE_8021Q:       #Checking for VLAN Tagged Packet
            src_vlan=vlan_header[0].vid    
        else:
            vlan_header_present = 0
            src_vlan='NULL'         

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        
        self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, str(src_vlan), eth.ethertype)
        actions = [] 
        
        match = None 
        
        if dpid == "0000000000000001":
            if in_port == 2:
                out_port = 1
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 1 and src_vlan=='NULL':
                out_port = 2
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src, vlan_vid = 0)
                actions=[parser.OFPActionOutput(out_port)]
            #Traffic comming from VNF
            elif in_port >= 4 and in_port <= 7:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            #traffic comming from inter-sw-link to VNFs
            elif in_port == 1 and src_vlan == 200:
                out_port = 4
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 1 and src_vlan == 201:
                out_port = 5
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 1 and src_vlan == 202:
                out_port = 6
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 1 and src_vlan == 203:
                out_port = 7
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            # Juju Servers Comunication    
            elif in_port == 1 and src_vlan == 100:
                out_port = 3
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 3 and src_vlan == 100:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, vlan_vid = (0x1000 | 100))
                actions=[parser.OFPActionOutput(out_port)]

            else:
                actions=[]
                out_port = 'null'
       
        if dpid == "0000000000000002":
            if in_port == 1 and src_vlan=='NULL':
                out_port = 2
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src, vlan_vid = 0)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 2 and eth.ethertype == ether_types.ETH_TYPE_ARP:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, eth_type = ether_types.ETH_TYPE_ARP)
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 2 and eth.ethertype == ether_types.ETH_TYPE_IP:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, eth_type = ether_types.ETH_TYPE_IP)
                actions=[parser.OFPActionOutput(out_port)]
            #Client to Vm1    
            elif in_port == 1 and src_vlan==200:
                out_port = 3
                match = parser.OFPMatch(in_port = in_port, vlan_vid = (0x1000 | 200))
                actions=[parser.OFPActionPopVlan(), parser.OFPActionOutput(out_port)]
            elif in_port == 3:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, eth_dst=dst, eth_src=src)
                actions=[parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | 200)), parser.OFPActionOutput(out_port)]
            #Juju Server comunication S2
            elif in_port == 1 and src_vlan==100:
                out_port = 4
                match = parser.OFPMatch(in_port = in_port, vlan_vid = (0x1000 | 100))
                actions=[parser.OFPActionOutput(out_port)]
            elif in_port == 4 and src_vlan==100:
                out_port = 1
                match = parser.OFPMatch(in_port = in_port, vlan_vid = (0x1000 | 100))
                actions=[parser.OFPActionOutput(out_port)]
            else:
                actions=[]
                out_port = 'null'

        

        #match = None
        if out_port != ofproto.OFPP_FLOOD and match == None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
        self.add_flow_send(in_port, out_port, msg, match=match, actions=actions)
