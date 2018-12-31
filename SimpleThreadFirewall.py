import collections
import time
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types

compare = lambda x, y: collections.Counter(x) == collections.Counter(y)

class SimpleThreadFirewall(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleThreadFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ip_list_of_list = []
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install default flow rule 
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # build the initial blacklist
        # configuration from the file
        self._build_internal_list()

        # install flow rules from internal list
        self._update_flowrules(datapath)


    def _wipe_flow_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                #priority=1,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        # keep default flow rule 
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _build_internal_list(self):
        print '\n #####  INITIAL CONFIGURATION  #####\n'
        print 'Source     Destination     Protocol    Action'
        print '------     -----------     --------    ------'
        with open('blacklist.txt', 'r') as f:
            for line in f.readlines():

                line_list = line.strip().split(',')
                line_list = [i.strip() for i in line_list]
                print str(line_list[0]) + '    ' + str(line_list[1]) +\
                            '      ' + str(line_list[2]) + '       ' + str(line_list[3])

                line_list[2] = self.convert_proto(line_list[2].strip())
                self.ip_list_of_list.append(line_list)

    def _internal_list_update(self):
        #compare your internal list with file
        temp_lst_of_lst = []

        with open('blacklist.txt', 'r') as f:
            for line in f.readlines():

                line_list = line.strip().split(',')
                line_list = [i.strip() for i in line_list]
                line_list[2] = self.convert_proto(line_list[2].strip())
                temp_lst_of_lst.append(line_list)

        if not (compare((map(tuple, temp_lst_of_lst)), (map(tuple, self.ip_list_of_list)))):
            self.ip_list_of_list = temp_lst_of_lst
            return True
        else:
            return False

    def _monitor(self):
        time.sleep(30)
        print '\n#####  Monitor Thread invoked  #####'
        while True:
            if self._internal_list_update():
                print '\nChanges to Firewall configuration detected'
                print 'New rules will be installed on the switch\n'
                print 'Source     Destination    Protocol    Action'
                print '------     -----------    --------    ------'

                for next_list in self.ip_list_of_list:
                    print str(next_list[0]) + '    ' +str(next_list[1])+ '    ' + \
                                self.convert_proto_num_to_str(next_list[2]) + '    ' + next_list[3]

                for dp in self.datapaths.values():
                    self._wipe_flow_table(dp)
                    self._update_flowrules(dp)
            #else:
            #    print "File not changed. Going to sleep.."
            hub.sleep(60)

    def _update_flowrules(self, datapath):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        for line in self.ip_list_of_list:
            print line[3]
            match = parser.OFPMatch(ipv4_src=line[0], \
                        ipv4_dst=line[1], ip_proto=line[2],\
                        eth_type=ether_types.ETH_TYPE_IP)
            if str(line[3]) == 'DENY':
                print'inside if'
                action = []
                priority = 10
            else:
                print 'in else'
                action = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                priority = 11

            self.add_flow(datapath, priority, match, action)


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

    def convert_proto(self, s):
        if s.lower() == 'icmp':
            return 1
        elif s.lower() == 'tcp':
            return 6
        elif s.lower() == 'udp':
            return 17
        elif s.lower() == 'igmp':
            return 88

    def convert_proto_num_to_str(self, num):
        if num == 1:
            return "icmp"
        elif num == 6:
            return "tcp"
        elif num == 17:
            return "udp"
        elif nu == 88:
            return "igmp"

