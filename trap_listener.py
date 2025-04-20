import logging
import queue
import yaml
from pysnmp.hlapi import *
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.smi import builder, view, compiler
from pysnmp.entity.rfc3413 import ntfrcv
import datetime
import os
import asyncio

class TrapListener:
    def __init__(self, config_file='config.yaml'):
        self.load_config(config_file)
        self.setup_logging()
        self.trap_queue = queue.Queue(maxsize=self.config['trap_listener']['queue_size'])
        self.blocked_oids = set(self.config['trap_listener']['blocked_oids'])
        self.blocked_senders = set(self.config['trap_listener']['blocked_senders'])
        
        # Initialize SNMP engine
        self.snmp_engine = engine.SnmpEngine()
        self.mib_builder = builder.MibBuilder()
        self.mib_view = view.MibViewController(self.mib_builder)
        
        # Initialize transport dispatcher
        self.transport_dispatcher = AsyncioDispatcher()
        self.snmp_engine.register_transport_dispatcher(self.transport_dispatcher)
        
    def load_config(self, config_file):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
            
    def setup_logging(self):
        log_dir = os.path.dirname(self.config['trap_listener']['log_file'])
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logging.basicConfig(
            filename=self.config['trap_listener']['log_file'],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('TrapListener')
        
    def is_blocked(self, sender_ip, trap_oid):
        return (sender_ip in self.blocked_senders or
                trap_oid in self.blocked_oids)
    
    def block_oid(self, oid):
        self.blocked_oids.add(oid)
        self.logger.info(f"Blocked OID: {oid}")
        
    def block_sender(self, sender_ip):
        self.blocked_senders.add(sender_ip)
        self.logger.info(f"Blocked sender: {sender_ip}")
        
    def unblock_oid(self, oid):
        self.blocked_oids.discard(oid)
        self.logger.info(f"Unblocked OID: {oid}")
        
    def unblock_sender(self, sender_ip):
        self.blocked_senders.discard(sender_ip)
        self.logger.info(f"Unblocked sender: {sender_ip}")

    def handle_trap(self, snmp_engine, stateReference, contextEngineId, contextName,
                   varBinds, cbCtx):
        """Handle incoming SNMP trap."""
        try:
            transport_domain, transport_address = snmp_engine.msgAndPduDsp.getTransportInfo(stateReference)
            sender_ip = transport_address[0]
            
            trap_data = {
                'source_address': sender_ip,
                'timestamp': datetime.datetime.now().isoformat(),
                'varbinds': []
            }

            for oid, val in varBinds:
                oid_str = str(oid)
                if self.is_blocked(sender_ip, oid_str):
                    self.logger.warning(f"Blocked trap from {sender_ip} with OID {oid_str}")
                    return

                trap_data['varbinds'].append({
                    'oid': oid_str,
                    'value': str(val)
                })

            # Log the trap
            self.logger.info(f"Received trap from {sender_ip}: {trap_data}")

            # Put trap in queue for processing
            try:
                self.trap_queue.put(trap_data, block=False)
            except queue.Full:
                self.logger.error("Trap queue is full, dropping trap")

        except Exception as e:
            self.logger.error(f"Error handling trap: {str(e)}")

    async def start(self):
        """Start the SNMP trap listener."""
        try:
            # Configure transport and security
            config.addTransport(
                self.snmp_engine,
                udp.domainName,
                udp.UdpTransport().openServerMode(('0.0.0.0', self.config['trap_listener']['port']))
            )

            # Configure community
            config.addV1System(self.snmp_engine, 'my-area', 'public')

            # Register callback
            ntfrcv.NotificationReceiver(self.snmp_engine, self.handle_trap)

            self.logger.info(f"Starting trap listener on port {self.config['trap_listener']['port']}")
            self.transport_dispatcher.jobStarted(1)
            
            # Run the dispatcher
            await self.transport_dispatcher.runDispatcher()

        except Exception as e:
            self.logger.error(f"Error starting trap listener: {str(e)}")
            raise

    def stop(self):
        """Stop the SNMP trap listener."""
        try:
            self.transport_dispatcher.jobFinished(1)
            self.logger.info("Trap listener stopped")
        except Exception as e:
            self.logger.error(f"Error stopping trap listener: {str(e)}")
            raise

if __name__ == '__main__':
    listener = TrapListener()
    try:
        asyncio.run(listener.start())
    except KeyboardInterrupt:
        listener.stop() 