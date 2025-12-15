"""
DetMeter Service - Core functionality
Simplified version that works
"""
import logging
import yaml
import aiohttp
import asyncio
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

class DetMeterService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('detmeter_svc')
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration"""
        try:
            with open('conf/local.yml', 'r') as f:
                config = yaml.safe_load(f)
                if config and 'detmeter' in config:
                    return config['detmeter']
        except:
            pass
        
        # Default configuration
        return {
            'siem_connections': {
                'splunk': {'enabled': False, 'endpoint': ''},
                'arcsight': {'enabled': False, 'endpoint': ''},
                'elastic': {'enabled': False, 'endpoint': ''},
                'qradar': {'enabled': False, 'endpoint': ''}
            },
            'default_timeframe': 24
        }
    
    async def analyze_operation(self, operation_id: str) -> Dict[str, Any]:
        """Analyze operation detection"""
        self.log.info(f'Analyzing operation: {operation_id}')
        
        # Get operation
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        if not operations:
            return {'error': 'Operation not found', 'success': False}
        
        operation = operations[0]
        
        # Extract techniques (simplified)
        techniques = self._extract_techniques(operation)
        
        # Query SIEMs
        siem_results = {}
        for siem_name, config in self.config.get('siem_connections', {}).items():
            if config.get('enabled'):
                result = await self._query_siem(siem_name, techniques)
                siem_results[siem_name] = result
        
        return {
            'success': True,
            'operation_id': operation.id,
            'operation_name': operation.name,
            'techniques_used': techniques,
            'siem_results': siem_results,
            'analysis_time': datetime.now().isoformat()
        }
    
    def _extract_techniques(self, operation) -> List[str]:
        """Extract technique IDs from operation"""
        techniques = []
        
        if not hasattr(operation, 'chain'):
            return techniques
        
        for link in operation.chain:
            if hasattr(link, 'ability') and link.ability:
                tech_id = getattr(link.ability, 'technique_id', None)
                if tech_id and tech_id not in techniques:
                    techniques.append(tech_id)
        
        return techniques
    
    async def _query_siem(self, siem_name: str, techniques: List[str]) -> Dict[str, Any]:
        """Query a SIEM (simulated for now)"""
        # Simulate network delay
        await asyncio.sleep(0.5)
        
        # Simulate detection based on SIEM type
        detection_rates = {
            'splunk': 0.7,
            'elastic': 0.75,
            'arcsight': 0.65,
            'qradar': 0.6
        }
        
        rate = detection_rates.get(siem_name.lower(), 0.5)
        random.seed(hash(siem_name))
        
        detected = []
        for tech in techniques:
            if random.random() < rate:
                detected.append(tech)
        
        return {
            'detected_techniques': detected,
            'detection_rate': len(detected) / len(techniques) * 100 if techniques else 0,
            'events_found': len(detected) * random.randint(1, 5),
            'query_time': random.uniform(0.5, 2.0)
        }
    
    async def get_siem_status(self) -> Dict[str, Any]:
        """Get SIEM connection status"""
        status = {}
        
        for siem_name, config in self.config.get('siem_connections', {}).items():
            siem_status = {
                'enabled': config.get('enabled', False),
                'configured': bool(config.get('endpoint')),
                'endpoint': config.get('endpoint', 'Not configured'),
                'last_checked': datetime.now().isoformat()
            }
            
            # Test connectivity if enabled
            if config.get('enabled') and config.get('endpoint'):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(config['endpoint'], timeout=3, ssl=False) as resp:
                            siem_status['reachable'] = resp.status < 500
                            siem_status['status'] = 'reachable' if resp.status < 500 else 'unreachable'
                except:
                    siem_status['reachable'] = False
                    siem_status['status'] = 'error'
            else:
                siem_status['status'] = 'disabled'
            
            status[siem_name] = siem_status
        
        return status
