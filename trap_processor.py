import logging
import yaml
import datetime
from pysnmp.smi import builder, view
import os
from dataclasses import dataclass
from typing import Optional, Dict, List
import json
import re

@dataclass
class Event:
    element_name: str
    instance_name: str
    event_name: str
    event: str
    event_text: str
    severity: str
    event_type: str
    create_time: str
    updated_time: str
    clear_time: Optional[str]
    enrich1: Optional[str]
    enrich2: Optional[str]
    enrich3: Optional[str]
    enrich4: Optional[str]
    enrich5: Optional[str]
    event_state: str = "Active"
    event_class: Optional[str] = None

class TrapProcessor:
    def __init__(self, trap_queue, config_file='config.yaml'):
        self.trap_queue = trap_queue
        self.load_config(config_file)
        self.setup_logging()
        self.events = []
        
        # Initialize SNMP MIB support
        self.mib_builder = builder.MibBuilder()
        self.mib_view = view.MibViewController(self.mib_builder)
        
    def load_config(self, config_file):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
            
    def setup_logging(self):
        log_dir = os.path.dirname(self.config['trap_processor']['log_file'])
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logging.basicConfig(
            filename=self.config['trap_processor']['log_file'],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('TrapProcessor')

    def get_varbind_value(self, varbinds, target_oid):
        """Extract value from varbinds for a given OID."""
        for varbind in varbinds:
            if varbind['oid'] == target_oid:
                return varbind['value']
        return None

    def extract_value_from_varbind(self, varbinds, rules: List[Dict]) -> str:
        """Extract value from varbinds using the provided rules."""
        for rule in rules:
            varbind_value = self.get_varbind_value(varbinds, rule['varbind_oid'])
            if varbind_value:
                match = re.search(rule['pattern'], str(varbind_value))
                if match:
                    return match.group(1)
        return 'unknown'

    def get_extraction_rules(self, trap_oid: str) -> Dict:
        """Get extraction rules for a specific trap OID or return default rules."""
        return self.config['trap_processor']['extraction_rules'].get(
            trap_oid,
            self.config['trap_processor']['default_extraction']
        )

    def get_enrichment_value(self, enrichment_config, varbinds):
        """Get enrichment value based on configuration."""
        if not enrichment_config:
            return None
            
        if enrichment_config.startswith('static:'):
            return enrichment_config.split(':', 1)[1]
        elif enrichment_config.startswith('varbind:'):
            oid = enrichment_config.split(':', 1)[1]
            return self.get_varbind_value(varbinds, oid)
        return None

    def process_trap(self, trap_data):
        """Process a single trap and convert it to an event."""
        try:
            # Get trap OID from varbinds
            trap_oid = None
            for varbind in trap_data['varbinds']:
                if varbind['oid'] == '.1.3.6.1.6.3.1.1.4.1.0':  # snmpTrapOID.0
                    trap_oid = varbind['value']
                    break

            # Get extraction rules for this trap type
            extraction_rules = self.get_extraction_rules(str(trap_oid))

            # Extract values using the rules
            instance_name = self.extract_value_from_varbind(
                trap_data['varbinds'],
                extraction_rules['instance_name']
            )
            event_name = self.extract_value_from_varbind(
                trap_data['varbinds'],
                extraction_rules['event_name']
            )
            severity = self.extract_value_from_varbind(
                trap_data['varbinds'],
                extraction_rules['severity']
            )

            # Determine event class based on trap OID
            event_class = self.config['trap_processor']['event_classes']['default']
            for vendor, oid_prefix in self.config['trap_processor']['event_classes'].items():
                if vendor != 'default' and str(trap_oid).startswith(oid_prefix):
                    event_class = f"{vendor.capitalize()}Alert"
                    break

            # Check if this is a clear trap
            is_clear_trap = any(
                str(trap_oid).endswith(clear_suffix)
                for clear_suffix in ['.0.1', '.0.2']  # Common clear trap suffixes
            )

            # Create event with extracted information
            event = Event(
                element_name=trap_data['source_address'],
                instance_name=instance_name,
                event_name=event_name,
                event=str(trap_data['varbinds']),
                event_text=str(trap_data['varbinds']),
                severity=severity,
                event_type='SNMP_TRAP',
                create_time=trap_data['timestamp'],
                updated_time=trap_data['timestamp'],
                clear_time=trap_data['timestamp'] if is_clear_trap else None,
                enrich1=self.get_enrichment_value(self.config['trap_processor']['enrichments']['enrich1'], trap_data['varbinds']),
                enrich2=self.get_enrichment_value(self.config['trap_processor']['enrichments']['enrich2'], trap_data['varbinds']),
                enrich3=self.get_enrichment_value(self.config['trap_processor']['enrichments']['enrich3'], trap_data['varbinds']),
                enrich4=self.get_enrichment_value(self.config['trap_processor']['enrichments']['enrich4'], trap_data['varbinds']),
                enrich5=self.get_enrichment_value(self.config['trap_processor']['enrichments']['enrich5'], trap_data['varbinds']),
                event_state="InActive" if is_clear_trap else "Active",
                event_class=event_class
            )
            
            self.events.append(event)
            self.logger.info(f"Processed trap into event: {event}")
            return event
            
        except Exception as e:
            self.logger.error(f"Error processing trap: {str(e)}")
            return None

    def get_events(self):
        """Return all processed events."""
        return self.events

    def process_queue(self):
        """Process all traps in the queue."""
        while True:
            try:
                trap_data = self.trap_queue.get(block=True)
                self.process_trap(trap_data)
            except Exception as e:
                self.logger.error(f"Error processing queue: {str(e)}")

    def to_dict(self):
        """Convert events to dictionary format for JSON serialization."""
        return {
            'events': [vars(event) for event in self.events]
        } 