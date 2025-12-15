"""
DetMeter Service - Official Implementation
"""
import logging
import yaml
import aiohttp
import asyncio
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin

class DetMeterService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('detmeter_svc')
        self.config = self._load_config()
        self.mitre_techniques = self._load_mitre_matrix()
        self._query_cache = {}
        self._cache_ttl = timedelta(minutes=10)
        
    def _load_config(self) -> Dict:
        """Load configuration"""
        default_config = {
            'siem_connections': {
                'splunk': {
                    'type': 'splunk',
                    'enabled': False,
                    'api_endpoint': '',
                    'token': '',
                    'verify_ssl': False
                },
                'arcsight': {
                    'type': 'arcsight',
                    'enabled': False,
                    'api_endpoint': '',
                    'username': '',
                    'password': '',
                    'verify_ssl': False
                },
                'elastic': {
                    'type': 'elastic',
                    'enabled': False,
                    'api_endpoint': '',
                    'username': '',
                    'password': '',
                    'verify_ssl': False
                },
                'qradar': {
                    'type': 'qradar',
                    'enabled': False,
                    'api_endpoint': '',
                    'token': '',
                    'verify_ssl': False
                }
            },
            'default_timeframe_hours': 24,
            'cache_enabled': True
        }
        
        try:
            # Try to load from detmeter.yml
            with open('conf/detmeter.yml', 'r') as f:
                config = yaml.safe_load(f)
                if config and 'detmeter' in config:
                    return {**default_config, **config['detmeter']}
        except:
            pass
        
        return default_config
    
    def _load_mitre_matrix(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK techniques"""
        # This is a basic set - you can expand this
        return {
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactics': ['execution']},
            'T1053': {'name': 'Scheduled Task/Job', 'tactics': ['persistence', 'execution']},
            'T1078': {'name': 'Valid Accounts', 'tactics': ['defense-evasion', 'persistence', 'privilege-escalation']},
            'T1082': {'name': 'System Information Discovery', 'tactics': ['discovery']},
            'T1518': {'name': 'Software Discovery', 'tactics': ['discovery']},
            'T1566': {'name': 'Phishing', 'tactics': ['initial-access']},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactics': ['persistence', 'privilege-escalation']},
            'T1110': {'name': 'Brute Force', 'tactics': ['credential-access']},
            'T1003': {'name': 'OS Credential Dumping', 'tactics': ['credential-access']},
            'T1047': {'name': 'Windows Management Instrumentation', 'tactics': ['execution']}
        }
    
    async def analyze_operation(self, operation_id: str, timeframe_hours: Optional[int] = None) -> Dict[str, Any]:
        """Main analysis function"""
        self.log.info(f'Analyzing operation: {operation_id}')
        
        # Get operation
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        if not operations:
            return {'error': f'Operation {operation_id} not found.', 'success': False}
        
        operation = operations[0]
        
        # Extract techniques
        techniques_data = await self._extract_techniques_with_details(operation)
        if not techniques_data:
            return {
                'warning': 'No techniques found',
                'operation_id': operation_id,
                'operation_name': operation.name,
                'success': True
            }
        
        # Determine timeframe
        if timeframe_hours is None:
            timeframe_hours = self.config.get('default_timeframe_hours', 24)
        
        start_time = operation.start if operation.start else datetime.now() - timedelta(hours=timeframe_hours)
        end_time = operation.finish if operation.finish else datetime.now()
        
        # Query SIEMs
        siem_results = {}
        enabled_siems = {k: v for k, v in self.config.get('siem_connections', {}).items() 
                        if v.get('enabled', False)}
        
        technique_ids = list(techniques_data.keys())
        
        for siem_name, siem_config in enabled_siems.items():
            result = await self._query_siem_techniques(
                siem_name, siem_config, technique_ids, start_time, end_time
            )
            
            if 'error' in result:
                siem_results[siem_name] = {
                    'error': result['error'],
                    'success': False,
                    'detection_rate': 0,
                    'events_found': 0
                }
            else:
                detected = result.get('detected_techniques', [])
                detection_rate = (len(detected) / len(technique_ids)) * 100 if technique_ids else 0
                
                siem_results[siem_name] = {
                    'success': True,
                    'techniques_detected': detected,
                    'detection_rate': round(detection_rate, 2),
                    'events_found': result.get('events_found', 0),
                    'query_time': result.get('query_time', 0)
                }
        
        return {
            'success': True,
            'operation_id': operation.id,
            'operation_name': operation.name,
            'operation_start': start_time.isoformat(),
            'operation_end': end_time.isoformat(),
            'techniques_used': {
                'total': len(technique_ids),
                'list': technique_ids,
                'details': techniques_data
            },
            'siem_results': siem_results,
            'analysis_time': datetime.now().isoformat()
        }
    
    async def _extract_techniques_with_details(self, operation) -> Dict[str, Dict]:
        """Extract techniques from operation"""
        techniques = {}
        
        if not hasattr(operation, 'chain'):
            return techniques
        
        for link in operation.chain:
            if hasattr(link, 'ability') and link.ability:
                tech_id = getattr(link.ability, 'technique_id', None)
                if not tech_id:
                    continue
                
                # Remove sub-technique numbers for comparison
                base_id = re.sub(r'\.\d+$', '', tech_id)
                
                if base_id in techniques:
                    techniques[base_id]['count'] += 1
                else:
                    mitre_info = self.mitre_techniques.get(base_id, {
                        'name': 'Unknown Technique',
                        'tactics': ['unknown']
                    })
                    
                    techniques[base_id] = {
                        'technique_id': base_id,
                        'full_id': tech_id,
                        'name': mitre_info['name'],
                        'tactics': mitre_info['tactics'],
                        'count': 1,
                        'ability': getattr(link.ability, 'name', 'Unknown')
                    }
        
        return techniques
    
    async def _query_siem_techniques(self, siem_name: str, config: Dict, 
                                    technique_ids: List[str], 
                                    start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query SIEM for techniques"""
        # Cache check
        cache_key = f"{siem_name}_{hash(tuple(technique_ids))}"
        if self.config.get('cache_enabled', True) and cache_key in self._query_cache:
            cached = self._query_cache[cache_key]
            if datetime.now() - cached['timestamp'] < self._cache_ttl:
                return cached['result']
        
        # Simulate query for now
        import random
        import time
        
        query_start = time.time()
        await asyncio.sleep(0.5)
        
        # Simulate detection
        random.seed(hash(siem_name))
        detected = []
        for tech in technique_ids:
            # Different SIEMs have different detection rates
            detection_probs = {
                'splunk': 0.7,
                'elastic': 0.75,
                'arcsight': 0.65,
                'qradar': 0.6
            }
            
            prob = detection_probs.get(config.get('type', 'unknown'), 0.5)
            if random.random() < prob:
                detected.append(tech)
        
        result = {
            'detected_techniques': detected,
            'events_found': len(detected) * random.randint(1, 5),
            'query_time': time.time() - query_start
        }
        
        # Cache result
        if self.config.get('cache_enabled', True):
            self._query_cache[cache_key] = {
                'timestamp': datetime.now(),
                'result': result
            }
        
        return result
    
    async def get_siem_status(self) -> Dict[str, Any]:
        """Get SIEM status"""
        status = {}
        
        for siem_name, config in self.config.get('siem_connections', {}).items():
            siem_status = {
                'configured': bool(config.get('api_endpoint')),
                'enabled': config.get('enabled', False),
                'type': config.get('type', 'unknown'),
                'endpoint': config.get('api_endpoint', 'Not configured'),
                'last_check': datetime.now().isoformat()
            }
            
            # Try to connect if enabled
            if config.get('enabled') and config.get('api_endpoint'):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(config['api_endpoint'], 
                                            timeout=5,
                                            ssl=config.get('verify_ssl', False)) as resp:
                            siem_status['reachable'] = resp.status < 500
                            siem_status['http_status'] = resp.status
                            siem_status['status'] = 'reachable' if resp.status < 500 else 'unreachable'
                except Exception as e:
                    siem_status['status'] = 'error'
                    siem_status['error'] = str(e)
            else:
                siem_status['status'] = 'disabled' if not config.get('enabled') else 'misconfigured'
            
            status[siem_name] = siem_status
        
        return status
