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
        self.port_to_tag = {3:100, 4:200, 5:201, 6:202, 7:203}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        #
        # This should disappear in the implementation sessions
        # Instead, you should move the decorator to the handler
        # for switch 2
        #
        if datapath.id == 1: # 'mport simulator'
            self.switch1_features_handler(ev)
        else:
            self.switch2_features_handler(ev)

    def add_flow(self, datapath, priority, match, actions,table_id=0,instructions=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        new_action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)

        if instructions is None:
            instructions = [ new_action ]
        else:
            instructions.insert(0, new_action)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=instructions,
                                    table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=instructions,
                                    table_id=table_id)
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
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        #
        # Just report packets that weren't handled by the switch tables
        #
        dpid = ev.msg.datapath.id
        in_port = ev.msg.match['in_port']
        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.info("Ignoring packet at Switch %d Port %d (%s -> %s)",dpid,in_port,eth.src,eth.dst)


    def drop_actions(self):
        return []

    def send_actions(self, output, parser,ofp):
        return [ parser.OFPActionOutput(ofp.OFPP_NORMAL, output) ]

    @staticmethod
    def goto_table(table_id, parser):
        return [parser.OFPInstructionGotoTable(table_id)]

    def switch1_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly. The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match=match, actions=actions)

        # Drop LLDP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        # Drop STDP BPDU
        match = parser.OFPMatch(eth_dst='01:80:c2:00:00:00')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        match = parser.OFPMatch(eth_dst='01:00:0c:cc:cc:cd')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        # Drop Broadcast Sources
        match = parser.OFPMatch(eth_src='ff:ff:ff:ff:ff:ff')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
    
        # untagged traffic to mport
        match = parser.OFPMatch(in_port=1, vlan_vid = 0)
        actions = self.send_actions(2,parser,ofproto)
        self.add_flow(datapath, 900, match=match, actions=actions)

        # all traffic from mport
        match = parser.OFPMatch(in_port=2)
        actions = self.send_actions(1,parser,ofproto)
        self.add_flow(datapath, 900, match=match, actions=actions)
        

        for port in self.port_to_tag.keys():
            # tagged traffic from vm1
            match = parser.OFPMatch(in_port=port)
            actions = self.send_actions(1, parser,ofproto)
            self.add_flow(datapath, 950, match=match, actions=actions)

            # tagged traffic to vm1
            match = parser.OFPMatch(in_port = 1, vlan_vid = (0x1000 | self.port_to_tag[port]))
            actions = self.send_actions(port, parser,ofproto)
            self.add_flow(datapath, 950, match=match, actions=actions)

    
    def switch2_features_handler(self, ev):
  
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match=match, actions=actions)

        # Drop LLDP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        # Drop STDP BPDU
        match = parser.OFPMatch(eth_dst='01:80:c2:00:00:00')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        match = parser.OFPMatch(eth_dst='01:00:0c:cc:cc:cd')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        # Drop Broadcast Sources
        match = parser.OFPMatch(eth_src='ff:ff:ff:ff:ff:ff')
        self.add_flow(datapath, 1000, match=match, actions=self.drop_actions())
        #
        # TODO: write the configuration of switch 2 here
        #
        
        # from interSwitch link untagged to laptop
        match = parser.OFPMatch(in_port=1, vlan_vid = 0)
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 950, match=match, actions=actions)
        # from interSwitch link tagged 100 to juju
        match = parser.OFPMatch(in_port=1, vlan_vid = (0x1000 | 100))
        actions = [parser.OFPActionOutput(4)]
        self.add_flow(datapath, 950, match=match, actions=actions)
        # from laptop to inter switch link
        match = parser.OFPMatch(in_port=2)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 950, match=match, actions=actions)
        # from juju to inter switch link 
        match = parser.OFPMatch(in_port=4)
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 950, match=match, actions=actions)
    
        for vlan in range(200,204):
            match = parser.OFPMatch(in_port=1, vlan_vid = (0x1000 | vlan))
            actions = [parser.OFPActionPopVlan()]
            self.add_flow(datapath, 950, match=match, actions=actions, instructions=self.goto_table(vlan,parser))
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 950, match=None, actions=actions, table_id = vlan)

            actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vlan)), parser.OFPActionOutput(1)]
            self.add_flow(datapath, 950, match=None, actions=actions, table_id = vlan + 5)
        
        match = parser.OFPMatch(in_port=3)
        self.add_flow(datapath, 950, match=match, actions=[], instructions=self.goto_table(205,parser))

