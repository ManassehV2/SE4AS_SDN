from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import requests
from simple_controller import SimpleController
from threading import Thread
import logging
import json
from datetime import datetime
from ryu.lib import hub

class FlowMonitor(SimpleController):
    """
    Controller that extends SimpleController to add flow statistics monitoring
    without affecting the core functionality
    """
    def __init__(self, *args, **kwargs):
        super(FlowMonitor, self).__init__(*args, **kwargs)
        self.monitor_url = 'http://analyze:5004/classify'
        
        # Enhanced logging setup
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler('flow_monitor.log')
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Statistics for monitoring
        self.total_flows_processed = 0
        self.total_bytes_processed = 0
        self.switches_stats = {}
        self.datapaths = {}
        
        # Start periodic stats collection
        self.stats_interval = 10  # collect stats every 10 seconds
        self.monitor_thread = hub.spawn(self._monitor)

    def _send_to_analyzer(self, flow_stats):
        """Send flow statistics to analyzer in a separate thread"""
        if not flow_stats:
            return
            
        try:
            # Log detailed flow statistics
            stats_summary = {
                'total_flows': len(flow_stats),
                'total_bytes': sum(stat['byte_count'] for stat in flow_stats),
                'total_packets': sum(stat['packet_count'] for stat in flow_stats),
                'timestamp': datetime.now().isoformat()
            }
            self.logger.info(f"Sending flow stats to analyzer: {json.dumps(stats_summary)}")
            
            response = requests.post(self.monitor_url, json={"flows": flow_stats})
            response.raise_for_status()
            
            # Log analyzer response
            if response.status_code == 200:
                self.logger.info(f"Analyzer response: {response.json()}")
            
            # Update monitoring statistics
            self.total_flows_processed += len(flow_stats)
            self.total_bytes_processed += stats_summary['total_bytes']
            
            # Log cumulative statistics
            self.logger.info(f"Cumulative stats - Flows: {self.total_flows_processed}, Bytes: {self.total_bytes_processed}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send flow stats to Analyzer: {str(e)}")
            self.logger.debug(f"Failed payload: {json.dumps(flow_stats)}")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply from switches"""
        body = ev.msg.body
        datapath_id = ev.msg.datapath.id
        
        # Log start of stats processing
        self.logger.info(f"Processing flow stats from switch {datapath_id}")
        
        flow_stats = []
        total_packets = 0
        total_bytes = 0
        
        for stat in body:
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            packet_rate = stat.packet_count / max(duration, 1e-6)
            byte_rate = stat.byte_count / max(duration, 1e-6)
            
            # Track switch-specific statistics
            if datapath_id not in self.switches_stats:
                self.switches_stats[datapath_id] = {'total_flows': 0, 'total_bytes': 0}
            
            self.switches_stats[datapath_id]['total_flows'] += 1
            self.switches_stats[datapath_id]['total_bytes'] += stat.byte_count
            
            total_packets += stat.packet_count
            total_bytes += stat.byte_count
            
            flow_data = {
                "datapath_id": datapath_id,
                "flow_duration": duration,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate
            }
            
            # Log suspicious flow rates
            if packet_rate > 1000 or byte_rate > 1000000:  # Adjust thresholds as needed
                self.logger.warning(f"High traffic flow detected on switch {datapath_id}:\n"
                                  f"Packet Rate: {packet_rate:.2f} pps\n"
                                  f"Byte Rate: {byte_rate:.2f} Bps")
            
            flow_stats.append(flow_data)
        
        # Log switch statistics
        self.logger.info(f"Switch {datapath_id} stats:\n"
                        f"Flows processed: {len(flow_stats)}\n"
                        f"Total packets: {total_packets}\n"
                        f"Total bytes: {total_bytes}\n"
                        f"Cumulative flows: {self.switches_stats[datapath_id]['total_flows']}\n"
                        f"Cumulative bytes: {self.switches_stats[datapath_id]['total_bytes']}")
        
        # Send flow stats to analyzer in a non-blocking way
        Thread(target=self._send_to_analyzer, args=(flow_stats,)).start()

    def _monitor(self):
        """Periodically request flow statistics from all switches."""
        while True:
            self.logger.info(f"Requesting flow stats from all switches (interval: {self.stats_interval}s)")
            for dp in self.datapaths.values():
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(self.stats_interval)
    
    def add_flow(self, datapath, priority, match, actions):
        """Override add_flow to request stats after adding flow"""
        # First call the parent's add_flow to maintain core functionality
        super(FlowMonitor, self).add_flow(datapath, priority, match, actions)
        
        # Store datapath for periodic monitoring
        self.datapaths[datapath.id] = datapath
