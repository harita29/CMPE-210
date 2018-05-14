# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import json
import time
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import ether_types
from ryu.lib import ofctl_v1_3

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable/{dpid}'
global get_return_data
global get_data_in_progress

class SimpleSwitchRest13Firewall(simple_switch_13.SimpleSwitch13):

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13Firewall, self).__init__(*args, **kwargs)
        self.switches = {}
        self.firewall_rules = []
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchFirewallController,
                      {simple_switch_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(SimpleSwitchRest13Firewall, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.fill_firewall_dict()
        self._monitor_n_update_flowrules_from_file(datapath)

    def fill_firewall_dict(self):
        with open('blacklist.txt','r') as f:
            for line in f.readlines():
                line_list = line.strip().split(',')
                print "fill_firewall_dict: line_list ==>" + str(line_list)
                proto_num = self.convert_proto(line_list[2].strip())
                print "proto_num = "+ str(proto_num)
                self.firewall_rules.append({'src_ip':line_list[0].strip(),
                                            'dst_ip':line_list[1].strip(), 
                                            'protocol':proto_num})
                print "fill_firewall_dict:firewall_rules ==>" + str(self.firewall_rules)

    def _monitor_n_update_flowrules_from_file(self, datapath):
        parser = datapath.ofproto_parser
        for line in self.firewall_rules:
            print"monitor_n_update_from_file:firewall_rules:line" + str(line)
            match = parser.OFPMatch(ipv4_src=line['src_ip'],
                                    ipv4_dst=line['dst_ip'],
                                    ip_proto=line['protocol'],
                                    eth_type=ether_types.ETH_TYPE_IP)
            action = []
            self.add_flow(datapath, 10, match, action)

    def _build_match_actions(self, dpid, entry):
        datapath = self.switches.get(dpid)
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        print "_build_match_actions: dpid ="
        print dpid
        print "_build_match_actions: entry ="
        print entry

        entry_src_ip = entry['src_ip']
        print"_build_match_actions:entry_src_ip:entry['src_ip']="
        print entry_src_ip
        print entry['src_ip']
        entry_dst_ip = entry['dst_ip']
        print entry_dst_ip
        print entry['dst_ip']
        entry_protocol = self.convert_proto(entry['protocol'])
        print entry_protocol
        print entry['protocol']

        entry_action = entry['action']
        print entry_action
        if entry_action == 'DENY':
            print "in DENY seciotn"
            actions = []
            priority = 10
        elif entry_action == 'ALLOW':
            print "in ALLOW section"
            actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            priority = 11

        match = parser.OFPMatch(ipv4_src=entry_src_ip,
                                ipv4_dst=entry_dst_ip,
                                ip_proto=entry_protocol,
                                eth_type=ether_types.ETH_TYPE_IP)
        self.add_flow(datapath, priority, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print "add_flow:"
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
        print mod
        datapath.send_msg(mod)

    def convert_proto(self, s):
        if s.lower() == 'icmp':
            return 1
        elif s.lower() == 'tcp':
            return 6
        elif s.lower() == 'udp':
            return 17
        elif s.lower() == 'igmp':
            return 88

    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})
        datapath = self.switches.get(dpid)

        entry_port = entry['port']
        entry_mac = entry['mac']

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():

                for mac, port in mac_table.items():

                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)

                mac_table.update({entry_mac: entry_port})
        return mac_table

    def inverse_proto(self, number):
        if number == 1:
            return "ICMP"
        elif number == 6:
            return "TCP"
        elif number == 17:
            return "UDP"
        elif number == 88:
            return "IGMP"

    def get_flow_rules(self, dpid):
        global get_data_in_progress
        datapath = self.switches.get(dpid)
        match = datapath.ofproto_parser.OFPMatch()
        stats = datapath.ofproto_parser.OFPFlowStatsRequest(datapath, 0, datapath.ofproto.OFPTT_ALL,
                                                            datapath.ofproto.OFPP_ANY,
                                                            datapath.ofproto.OFPG_ANY, 0, 0, match)
        datapath.send_msg(stats)
        get_data_in_progress = True
        #while get_data_in_progress:
        #      print "Get data in progress"
        #return get_return_data

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        global get_data_in_progress
        global get_return_data
        flow_rules = []
        for stats in ev.msg.body:
            actions = ofctl_v1_3.actions_to_str(stats.instructions)
            match = ofctl_v1_3.match_to_str(stats.match)
            if not actions:
                actions = "DROP"
            elif "CONTROLLER" in actions[0]:
                actions = "CONTROLLER"
            else:
                actions = "ALLOW"
            if 'nw_proto' in match:
                protocol = self.inverse_proto(int(match['nw_proto']))
                match['nw_proto'] = protocol
            match["actions"] = actions
            if "dl_type" in match:
                del match["dl_type"]
            #match.update(actions)
            flow_rules.append(match)
        get_return_data = list(flow_rules)
        print get_return_data
        get_data_in_progress = False

    def delete_flow(self, dpid):
        datapath = self.switches.get(dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)



class SimpleSwitchFirewallController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchFirewallController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]
    """
    @route('simpleswitch', url, methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)
    """
    @route('simpleswitch', url, methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):
        print "put_mac_table: req ="
        print req
        print "\n"
        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        try:
            new_entry = req.json if req.body else {}
            print"new_entry = "
            print new_entry
            print"\n"

        except ValueError:
            raise Response(status=400)

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        try:
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)


    @route('simpleswitch', url, methods=['PUT'],
            requirements={'dpid': dpid_lib.DPID_PATTERN})
    def modify_flow_rule(self, req, **kwargs):
        print "modify_flow_rule:req = "
        print req

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        print "modify_flow_rule: dpid ="
        print dpid
        try:
            new_entry = req.json if req.body else {}
            print "modify_flow_rule: new_entry ="
            print new_entry
        except ValueError:
            return Response(status=400)

        if dpid not in simple_switch.switches:
            return Response(status=404)

        try:
            simple_switch._build_match_actions(dpid, new_entry)
            return Response(status=200)
        except Exception as e:
            print e
            return Response(status=500)

    @route('simpleswitch', url, methods=['GET'],
            requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_flow_rules(self, req, **kwargs):
        global get_data_in_progress
        global get_return_data
        get_data_in_progress = False
        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in simple_switch.switches:
            return Response(status=404)
        try:
            if not get_data_in_progress:
               get_return_data = []
               simple_switch.get_flow_rules(dpid)
               if len(get_return_data) == 0:
                   time.sleep(1)
               body = json.dumps(get_return_data)
               return Response(content_type='application/json', body=body)
        except Exception as e:
            print e
            return Response(status=500)

    @route('simpleswitch', url, methods=['DELETE'],
            requirements={'dpid': dpid_lib.DPID_PATTERN})
    def delete_flow_rules(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in simple_switch.switches:
            return Response(status=404)
        try:
            simple_switch.delete_flow(dpid)
            return Response(status=200)
        except Exception as e:
            print e
            return Response(status=500)


