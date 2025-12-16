"""
Core service for DetMeter plugin.
Handles SIEM integrations and detection logic.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional
from aiohttp import ClientSession, ClientError

class SIEMInterface:
    """Abstract base class for SIEM integrations"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.log = logging.getLogger('detmeter')
        
    async def connect(self):
        """Initialize connection to SIEM"""
        self.session = ClientSession()
        
    async def disconnect(self):
        """Close connection"""
        if self.session:
            await self.session.close()
            
    async def query_detections(self, operation_id: str, command: str, timestamp: str) -> List[Dict]:
        """
        Query SIEM for detections related to the operation.
        Returns list of detection events or empty list.
        """
        raise NotImplementedError
        
    async def format_detection(self, raw_event: Dict) -> Dict:
        """Convert SIEM-specific event to standardized format"""
        raise NotImplementedError
        
    async def test_connection(self) -> Dict:
        """Test connection to SIEM"""
        raise NotImplementedError


class SplunkInterface(SIEMInterface):
    """Splunk SIEM integration"""
    
    async def query_detections(self, operation_id: str, command: str, timestamp: str) -> List[Dict]:
        try:
            search_query = f'search earliest=-5m latest=now() "{command[:100]}"'
            
            headers = {
                'Authorization': f'Bearer {self.config.get("api_key")}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.post(
                f'{self.config["api_endpoint"]}/services/search/jobs',
                headers=headers,
                json={'search': search_query}
            ) as resp:
                if resp.status != 201:
                    self.log.error(f'Splunk search failed: {resp.status}')
                    return []
                    
            # In production: Poll for results and parse
            # For demo: Return mock detection
            return [{
                '_raw': f'Detected command execution: {command[:50]}...',
                '_time': datetime.utcnow().isoformat(),
                'source': 'caldera',
                'sourcetype': 'caldera:detection',
                'rule_name': 'COMMAND_EXECUTION'
            }]
            
        except ClientError as e:
            self.log.error(f'Splunk query failed: {e}')
            return []
            
    async def format_detection(self, raw_event: Dict) -> Dict:
        return {
            'rule_id': raw_event.get('rule_name', 'SPLUNK_DETECTION'),
            'timestamp': raw_event.get('_time', datetime.utcnow().isoformat()),
            'severity': 'high',
            'source': 'Splunk',
            'raw_event': raw_event.get('_raw', ''),
            'confidence': 0.8
        }
        
    async def test_connection(self) -> Dict:
        try:
            headers = {
                'Authorization': f'Bearer {self.config.get("api_key")}',
            }
            
            async with self.session.get(
                f'{self.config["api_endpoint"]}/services/server/info',
                headers=headers
            ) as resp:
                if resp.status == 200:
                    return {'status': 'success', 'message': 'Connected to Splunk'}
                else:
                    return {'status': 'error', 'message': f'Connection failed: {resp.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class QRadarInterface(SIEMInterface):
    """IBM QRadar integration"""
    
    async def query_detections(self, operation_id: str, command: str, timestamp: str) -> List[Dict]:
        try:
            aql_query = f'''
            SELECT * FROM events 
            WHERE UTF8(payload) CONTAINS '{command[:50]}'
            LAST 5 MINUTES
            '''
            
            headers = {
                'SEC': self.config.get('api_key'),
                'Content-Type': 'application/json',
                'Version': '15.0'
            }
            
            async with self.session.post(
                f'{self.config["api_endpoint"]}/api/ariel/searches',
                headers=headers,
                json={'query_expression': aql_query}
            ) as resp:
                if resp.status != 201:
                    return []
                    
            # Mock detection for demonstration
            return [{
                'starttime': datetime.utcnow().isoformat(),
                'qid': 123456,
                'category': 1001,
                'rulename': 'Suspicious Command Execution',
                'severity': 5
            }]
            
        except ClientError as e:
            self.log.error(f'QRadar query failed: {e}')
            return []
            
    async def format_detection(self, raw_event: Dict) -> Dict:
        return {
            'rule_id': f"QRADAR_{raw_event.get('qid', 'UNKNOWN')}",
            'timestamp': raw_event.get('starttime', datetime.utcnow().isoformat()),
            'severity': raw_event.get('severity', 3),
            'source': 'QRadar',
            'rule_name': raw_event.get('rulename', 'QRadar Detection'),
            'confidence': 0.7
        }
        
    async def test_connection(self) -> Dict:
        try:
            headers = {
                'SEC': self.config.get('api_key'),
                'Version': '15.0'
            }
            
            async with self.session.get(
                f'{self.config["api_endpoint"]}/api/gui_app_framework/application_definitions',
                headers=headers
            ) as resp:
                if resp.status == 200:
                    return {'status': 'success', 'message': 'Connected to QRadar'}
                else:
                    return {'status': 'error', 'message': f'Connection failed: {resp.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class ElasticInterface(SIEMInterface):
    """Elastic SIEM integration"""
    
    async def query_detections(self, operation_id: str, command: str, timestamp: str) -> List[Dict]:
        try:
            es_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"message": command[:100]}},
                            {"range": {"@timestamp": {"gte": "now-5m"}}}
                        ]
                    }
                }
            }
            
            headers = {
                'Authorization': f'ApiKey {self.config.get("api_key")}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.post(
                f'{self.config["api_endpoint"]}/_search',
                headers=headers,
                json=es_query
            ) as resp:
                if resp.status != 200:
                    return []
                    
                data = await resp.json()
                hits = data.get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits[:5]]
                
        except ClientError as e:
            self.log.error(f'Elastic query failed: {e}')
            return []
            
    async def format_detection(self, raw_event: Dict) -> Dict:
        return {
            'rule_id': raw_event.get('rule', {}).get('id', 'ELASTIC_RULE'),
            'timestamp': raw_event.get('@timestamp', datetime.utcnow().isoformat()),
            'severity': raw_event.get('event', {}).get('severity', 3),
            'source': 'Elastic',
            'rule_name': raw_event.get('rule', {}).get('name', 'Elastic Detection'),
            'confidence': raw_event.get('event', {}).get('risk_score', 50) / 100
        }
        
    async def test_connection(self) -> Dict:
        try:
            headers = {
                'Authorization': f'ApiKey {self.config.get("api_key")}',
            }
            
            async with self.session.get(
                f'{self.config["api_endpoint"]}/',
                headers=headers
            ) as resp:
                if resp.status == 200:
                    return {'status': 'success', 'message': 'Connected to Elastic'}
                else:
                    return {'status': 'error', 'message': f'Connection failed: {resp.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class DetMeterService:
    """Core service for DetMeter plugin"""
    
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.event_svc = services.get('event_svc')
        self.log = logging.getLogger('detmeter')
        
        # Storage
        self.detections = {
            'blue': [],   # Blue agent detections
            'siem': []    # SIEM detections
        }
        
        # Configuration
        self.siem_config = {
            'selected_siem': None,
            'api_endpoint': None,
            'api_key': None,
            'verify_ssl': True,
            'enabled': False
        }
        
        self.siem_client = None
        
        # SIEM mappings
        self.siem_interfaces = {
            'Splunk': SplunkInterface,
            'QRadar': QRadarInterface,
            'Elastic': ElasticInterface
        }
        
    async def enable(self):
        """Initialize service"""
        # Listen for operation events
        await self.event_svc.observe_event(self._handle_operation_event, exchange='operation')
        self.log.info('DetMeter service enabled')
        
    async def _handle_operation_event(self, event, **kwargs):
        """Handle operation events"""
        if event == 'operation/link':
            link = kwargs.get('link')
            if link:
                await self._record_blue_detection(link)
                await self._query_siem_detections(link)
                
        elif event == 'operation/complete':
            operation = kwargs.get('operation')
            if operation:
                await self._final_siem_query(operation.id)
                
    async def _record_blue_detection(self, link):
        """Record Blue agent detection"""
        detection = {
            'id': f"blue_{link.id}",
            'operation_id': link.operation,
            'link_id': link.id,
            'timestamp': datetime.utcnow().isoformat(),
            'command': link.command,
            'ability': link.ability.ability_id if link.ability else None,
            'agent': link.paw,
            'status': 'executed'
        }
        self.detections['blue'].append(detection)
        self.log.debug(f'Recorded blue detection: {detection["id"]}')
        
    async def _get_siem_client(self) -> Optional[SIEMInterface]:
        """Get configured SIEM client"""
        if not self.siem_config['selected_siem'] or not self.siem_config['api_endpoint']:
            return None
            
        if self.siem_client and isinstance(self.siem_client, self.siem_interfaces.get(self.siem_config['selected_siem'])):
            return self.siem_client
            
        # Create new client
        siem_class = self.siem_interfaces.get(self.siem_config['selected_siem'])
        if not siem_class:
            self.log.error(f'Unsupported SIEM: {self.siem_config["selected_siem"]}')
            return None
            
        self.siem_client = siem_class(self.siem_config)
        await self.siem_client.connect()
        return self.siem_client
        
    async def _query_siem_detections(self, link):
        """Query SIEM for detections"""
        siem_client = await self._get_siem_client()
        if not siem_client:
            return
            
        try:
            raw_events = await siem_client.query_detections(
                link.operation,
                link.command,
                datetime.utcnow().isoformat()
            )
            
            for raw_event in raw_events:
                formatted = await siem_client.format_detection(raw_event)
                
                detection = {
                    'id': f"siem_{len(self.detections['siem'])}",
                    'operation_id': link.operation,
                    'timestamp': formatted['timestamp'],
                    'source': self.siem_config['selected_siem'],
                    'details': formatted,
                    'confidence': formatted.get('confidence', 0.5),
                    'matched_blue_id': f"blue_{link.id}"
                }
                
                self.detections['siem'].append(detection)
                self.log.info(f'SIEM detection found: {detection["id"]}')
                
        except Exception as e:
            self.log.error(f'SIEM query failed: {e}')
            
    async def _final_siem_query(self, operation_id):
        """Final query after operation completes"""
        siem_client = await self._get_siem_client()
        if not siem_client:
            return
            
        try:
            # Broad search for operation
            raw_events = await siem_client.query_detections(
                operation_id,
                f"operation_{operation_id}",
                datetime.utcnow().isoformat()
            )
            
            for raw_event in raw_events:
                formatted = await siem_client.format_detection(raw_event)
                
                # Avoid duplicates
                existing = any(
                    d['details']['rule_id'] == formatted['rule_id'] 
                    and d['operation_id'] == operation_id
                    for d in self.detections['siem']
                )
                
                if not existing:
                    detection = {
                        'id': f"siem_post_{len(self.detections['siem'])}",
                        'operation_id': operation_id,
                        'timestamp': formatted['timestamp'],
                        'source': self.siem_config['selected_siem'],
                        'details': formatted,
                        'confidence': formatted.get('confidence', 0.5),
                        'matched_blue_id': None
                    }
                    self.detections['siem'].append(detection)
                    
        except Exception as e:
            self.log.error(f'Final SIEM query failed: {e}')
            
    # Public API methods
    async def get_detections(self, operation_id: str = None) -> Dict:
        """Get detections with optional filtering"""
        result = {'blue': [], 'siem': []}
        
        for blue in self.detections['blue']:
            if operation_id and blue['operation_id'] != operation_id:
                continue
            result['blue'].append(blue)
            
        for siem in self.detections['siem']:
            if operation_id and siem['operation_id'] != operation_id:
                continue
            result['siem'].append(siem)
            
        return result
        
    async def get_summary(self, operation_id: str = None) -> Dict:
        """Generate detection summary"""
        detections = await self.get_detections(operation_id)
        
        summary = {
            'total': {
                'blue': len(detections['blue']),
                'siem': len(detections['siem']),
                'coverage': len(detections['siem']) / max(len(detections['blue']), 1) * 100
            },
            'by_operation': {},
            'timeline': []
        }
        
        # Group by operation
        blue_by_op = {}
        for det in detections['blue']:
            blue_by_op.setdefault(det['operation_id'], []).append(det)
            
        siem_by_op = {}
        for det in detections['siem']:
            siem_by_op.setdefault(det['operation_id'], []).append(det)
            
        # Calculate per-operation stats
        for op_id in set(list(blue_by_op.keys()) + list(siem_by_op.keys())):
            blue_dets = blue_by_op.get(op_id, [])
            siem_dets = siem_by_op.get(op_id, [])
            
            # Calculate average detection time
            detection_times = []
            for siem_det in siem_dets:
                siem_time = datetime.fromisoformat(siem_det['timestamp'].replace('Z', '+00:00'))
                for blue_det in blue_dets:
                    blue_time = datetime.fromisoformat(blue_det['timestamp'].replace('Z', '+00:00'))
                    if siem_time > blue_time:
                        delay = (siem_time - blue_time).total_seconds()
                        detection_times.append(delay)
                        
            avg_delay = sum(detection_times) / len(detection_times) if detection_times else 0
            
            summary['by_operation'][op_id] = {
                'blue_count': len(blue_dets),
                'siem_count': len(siem_dets),
                'coverage': len(siem_dets) / max(len(blue_dets), 1) * 100,
                'avg_delay_seconds': avg_delay
            }
            
        # Prepare timeline data
        timeline_data = []
        for blue in detections['blue'][:50]:  # Limit for performance
            timeline_data.append({
                'type': 'blue',
                'time': blue['timestamp'],
                'operation': blue['operation_id'],
                'label': f'Blue: {blue["command"][:30]}...'
            })
            
        for siem in detections['siem'][:50]:
            timeline_data.append({
                'type': 'siem',
                'time': siem['timestamp'],
                'operation': siem['operation_id'],
                'label': f'SIEM: {siem["details"]["rule_id"]}'
            })
            
        timeline_data.sort(key=lambda x: x['time'])
        summary['timeline'] = timeline_data
        
        return summary
        
    async def test_siem_connection(self, config: Dict) -> Dict:
        """Test connection to SIEM"""
        siem_class = self.siem_interfaces.get(config.get('selected_siem'))
        if not siem_class:
            return {'status': 'error', 'message': 'Unsupported SIEM'}
            
        try:
            client = siem_class(config)
            await client.connect()
            result = await client.test_connection()
            await client.disconnect()
            return result
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
            
    async def update_config(self, config: Dict):
        """Update SIEM configuration"""
        old_siem = self.siem_config.get('selected_siem')
        
        # Disconnect old client if SIEM changed
        if old_siem != config.get('selected_siem') and self.siem_client:
            await self.siem_client.disconnect()
            self.siem_client = None
            
        self.siem_config.update(config)
        self.log.info(f'SIEM config updated: {config.get("selected_siem")}')
        
    async def get_config(self) -> Dict:
        """Get current configuration"""
        return self.siem_config
        
    async def get_operations(self) -> List[Dict]:
        """Get list of operations for filtering"""
        operations = await self.data_svc.locate('operations')
        return [
            {
                'id': op.id,
                'name': op.name,
                'start': op.start.isoformat() if op.start else None,
                'state': op.state,
                'group': op.group
            }
            for op in operations
        ]
        
    async def clear_data(self, operation_id: str = None):
        """Clear detection data"""
        if operation_id:
            self.detections['blue'] = [d for d in self.detections['blue'] if d['operation_id'] != operation_id]
            self.detections['siem'] = [d for d in self.detections['siem'] if d['operation_id'] != operation_id]
        else:
            self.detections = {'blue': [], 'siem': []}
        self.log.info(f'Cleared detection data for operation: {operation_id or "all"}')
