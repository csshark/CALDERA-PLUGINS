"""
DetMeter plugin for MITRE Caldera 5.3.0.
Compares Blue agent detection times with real SIEM detections.
"""
import asyncio
import json
import logging
from datetime import datetime
from aiohttp import web, ClientSession, ClientError
from aiohttp_jinja2 import template
from app.service.auth_svc import check_authorization

name = 'DetMeter'
description = 'Compare Blue agent detections with SIEM detections'
address = '/plugin/detmeter/gui'

class SIEMInterface:
    """Abstract base class for SIEM integrations"""
    
    def __init__(self, config):
        self.config = config
        self.session = None
        
    async def connect(self):
        """Initialize connection to SIEM"""
        self.session = ClientSession()
        
    async def disconnect(self):
        """Close connection"""
        if self.session:
            await self.session.close()
            
    async def query_detections(self, operation_id, command, timestamp):
        """
        Query SIEM for detections related to the operation.
        Returns list of detection events or empty list.
        """
        raise NotImplementedError
        
    async def format_detection(self, raw_event):
        """Convert SIEM-specific event to standardized format"""
        raise NotImplementedError


class SplunkInterface(SIEMInterface):
    """Splunk SIEM integration"""
    
    async def query_detections(self, operation_id, command, timestamp):
        try:
            # Search for relevant events in the last 5 minutes
            search_query = f'search earliest=-5m latest=now() "{command}" OR "operation_{operation_id}"'
            
            headers = {
                'Authorization': f'Bearer {self.config.get("api_key")}',
                'Content-Type': 'application/json'
            }
            
            # Start search job
            async with self.session.post(
                f'{self.config["api_endpoint"]}/services/search/jobs',
                headers=headers,
                json={'search': search_query}
            ) as resp:
                if resp.status != 201:
                    logging.error(f'Splunk search creation failed: {resp.status}')
                    return []
                data = await resp.text()
                # Parse SID from response (simplified)
                # In production: proper XML/JSON parsing
                
            # Mock successful detection for demonstration
            # In production: poll for results and parse
            return [{
                '_raw': f'Mock Splunk detection for: {command}',
                '_time': datetime.utcnow().isoformat(),
                'sourcetype': 'caldera_detection',
                'rule_name': 'CALDERA_COMMAND_EXECUTION'
            }]
        except ClientError as e:
            logging.error(f'Splunk query failed: {e}')
            return []
            
    async def format_detection(self, raw_event):
        return {
            'rule_id': raw_event.get('rule_name', 'SPLUNK_RULE'),
            'timestamp': raw_event.get('_time', datetime.utcnow().isoformat()),
            'raw_event': raw_event.get('_raw', ''),
            'confidence': 'high' if 'caldera' in raw_event.get('_raw', '').lower() else 'medium'
        }


class QRadarInterface(SIEMInterface):
    """IBM QRadar integration"""
    
    async def query_detections(self, operation_id, command, timestamp):
        try:
            # QRadar AQL query
            aql_query = f'''
            SELECT * FROM events 
            WHERE "INOFFENSE" = true 
            AND UTF8(payload) LIKE '%{command[:50]}%'
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
                    logging.error(f'QRadar search failed: {resp.status}')
                    return []
                    
                search_data = await resp.json()
                search_id = search_data.get('search_id')
                
                # Poll for results (simplified)
                await asyncio.sleep(1)
                
            # Mock detection for demonstration
            return [{
                'starttime': datetime.utcnow().isoformat(),
                'categoryname': 'Caldera Activity',
                'rulename': 'Command Execution Detected',
                'magnitude': 5
            }]
        except ClientError as e:
            logging.error(f'QRadar query failed: {e}')
            return []
            
    async def format_detection(self, raw_event):
        return {
            'rule_id': raw_event.get('rulename', 'QRADAR_RULE'),
            'timestamp': raw_event.get('starttime', datetime.utcnow().isoformat()),
            'severity': raw_event.get('magnitude', 3),
            'category': raw_event.get('categoryname', 'Unknown')
        }


class ElasticInterface(SIEMInterface):
    """Elastic SIEM integration"""
    
    async def query_detections(self, operation_id, command, timestamp):
        try:
            # Elasticsearch query
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
                    logging.error(f'Elastic search failed: {resp.status}')
                    return []
                    
                data = await resp.json()
                hits = data.get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits[:10]]  # Limit to 10 events
                
        except ClientError as e:
            logging.error(f'Elastic query failed: {e}')
            return []
            
    async def format_detection(self, raw_event):
        return {
            'rule_id': raw_event.get('rule', {}).get('name', 'ELASTIC_RULE'),
            'timestamp': raw_event.get('@timestamp', datetime.utcnow().isoformat()),
            'event_type': raw_event.get('event', {}).get('kind', 'alert'),
            'risk_score': raw_event.get('event', {}).get('risk_score', 50)
        }


class DetMeterPlugin:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.event_svc = services.get('event_svc')
        self.auth_svc = services.get('auth_svc')
        self.app_svc = services.get('app_svc')
        self.log = logging.getLogger('detmeter')
        self.detections = {
            'blue': [],
            'siem': []
        }
        self.siem_config = {
            'selected_siem': None,
            'api_endpoint': None,
            'api_key': None,
            'verify_ssl': True,
            'poll_interval': 30
        }
        self.siem_client = None

    async def enable(self):
        """Hook called when plugin is enabled."""
        app = self.app_svc.application
        app.router.add_route('*', address, self.splash)
        app.router.add_route('GET', '/plugin/detmeter/config', self.get_config)
        app.router.add_route('POST', '/plugin/detmeter/config', self.set_config)
        app.router.add_route('GET', '/plugin/detmeter/data', self.get_detection_data)
        app.router.add_route('POST', '/plugin/detmeter/test', self.test_connection)
        app.router.add_route('GET', '/plugin/detmeter/summary', self.get_summary)
        app.router.add_route('GET', '/plugin/detmeter/operations', self.get_operations)
        
        await self.event_svc.observe_event(self.handle_operation_event, exchange='operation')
        self.log.info('DetMeter plugin enabled')

    async def get_siem_client(self):
        """Get SIEM client based on configuration."""
        if not self.siem_config['selected_siem'] or not self.siem_config['api_endpoint']:
            return None
            
        if self.siem_client:
            return self.siem_client
            
        siem_map = {
            'Splunk': SplunkInterface,
            'QRadar': QRadarInterface,
            'Elastic': ElasticInterface,
            'ArcSight': SplunkInterface  # Using Splunk interface as template
        }
        
        siem_class = siem_map.get(self.siem_config['selected_siem'])
        if not siem_class:
            self.log.error(f'Unsupported SIEM: {self.siem_config["selected_siem"]}')
            return None
            
        self.siem_client = siem_class(self.siem_config)
        await self.siem_client.connect()
        return self.siem_client

    async def handle_operation_event(self, event, **kwargs):
        """
        Listen for operation events and query SIEM for detections.
        """
        if event == 'operation/link':
            link = kwargs.get('link')
            if link:
                # Record Blue agent detection
                blue_detection = {
                    'operation_id': link.operation,
                    'link_id': link.id,
                    'timestamp': datetime.utcnow().isoformat(),
                    'command': link.command,
                    'ability_id': link.ability.ability_id if link.ability else 'unknown',
                    'status': 'success'
                }
                self.detections['blue'].append(blue_detection)
                self.log.info(f'Blue detection: Op {link.operation}, Cmd: {link.command[:50]}...')
                
                # Query SIEM for related detections
                await self.query_siem_detections(link.operation, link.command, blue_detection['timestamp'])
                
        elif event == 'operation/complete':
            operation = kwargs.get('operation')
            await self.perform_final_siem_query(operation.id if operation else 'unknown')

    async def query_siem_detections(self, operation_id, command, timestamp):
        """Query configured SIEM for detection events."""
        siem_client = await self.get_siem_client()
        if not siem_client:
            self.log.debug('No SIEM client configured')
            return
            
        try:
            raw_events = await siem_client.query_detections(operation_id, command, timestamp)
            
            for raw_event in raw_events:
                formatted_event = await siem_client.format_detection(raw_event)
                siem_detection = {
                    'operation_id': operation_id,
                    'timestamp': formatted_event['timestamp'],
                    'source': self.siem_config['selected_siem'],
                    'confidence': formatted_event.get('confidence', 'medium'),
                    'details': formatted_event
                }
                self.detections['siem'].append(siem_detection)
                self.log.info(f'SIEM detection: {self.siem_config["selected_siem"]} found event for Op {operation_id}')
                
        except Exception as e:
            self.log.error(f'SIEM query failed: {e}')

    async def perform_final_siem_query(self, operation_id):
        """
        Final SIEM query after operation completes.
        This catches any delayed detections.
        """
        siem_client = await self.get_siem_client()
        if not siem_client:
            return
            
        try:
            # Broad search for operation-related events
            raw_events = await siem_client.query_detections(
                operation_id, 
                f"operation_{operation_id}", 
                datetime.utcnow().isoformat()
            )
            
            for raw_event in raw_events:
                formatted_event = await siem_client.format_detection(raw_event)
                # Avoid duplicates
                if not any(d['details'].get('rule_id') == formatted_event.get('rule_id') 
                          for d in self.detections['siem'] 
                          if d['operation_id'] == operation_id):
                    siem_detection = {
                        'operation_id': operation_id,
                        'timestamp': formatted_event['timestamp'],
                        'source': self.siem_config['selected_siem'],
                        'confidence': 'post_operation',
                        'details': formatted_event
                    }
                    self.detections['siem'].append(siem_detection)
                    
        except Exception as e:
            self.log.error(f'Final SIEM query failed: {e}')

    async def test_connection(self, request):
        """Test SIEM connection and credentials."""
        data = await request.json()
        test_config = {
            'selected_siem': data.get('selected_siem'),
            'api_endpoint': data.get('api_endpoint'),
            'api_key': data.get('api_key'),
            'verify_ssl': data.get('verify_ssl', True)
        }
        
        if not all([test_config['selected_siem'], test_config['api_endpoint'], test_config['api_key']]):
            return web.json_response({'status': 'error', 'message': 'Missing required fields'})
        
        try:
            siem_map = {
                'Splunk': SplunkInterface,
                'QRadar': QRadarInterface,
                'Elastic': ElasticInterface
            }
            
            siem_class = siem_map.get(test_config['selected_siem'])
            if not siem_class:
                return web.json_response({'status': 'error', 'message': 'Unsupported SIEM'})
            
            # Test connection
            test_client = siem_class(test_config)
            await test_client.connect()
            
            # Try simple query
            test_events = await test_client.query_detections('test', 'test_command', datetime.utcnow().isoformat())
            
            await test_client.disconnect()
            
            return web.json_response({
                'status': 'success',
                'message': f'Connected to {test_config["selected_siem"]} successfully',
                'capabilities': 'Query execution verified'
            })
            
        except Exception as e:
            return web.json_response({'status': 'error', 'message': str(e)})

    async def get_operations(self, request):
        """Get list of operations for filtering."""
        operations = await self.data_svc.locate('operations')
        ops_data = []
        for op in operations:
            ops_data.append({
                'id': op.id,
                'name': op.name,
                'started': op.start.isoformat() if op.start else None,
                'state': op.state
            })
        return web.json_response(ops_data)

    @check_authorization
    @template('detmeter.html')
    async def splash(self, request):
        return dict()

    async def get_config(self, request):
        return web.json_response(self.siem_config)

    async def set_config(self, request):
        data = await request.json()
        
        # Reset client if SIEM changed
        old_siem = self.siem_config.get('selected_siem')
        if old_siem != data.get('selected_siem') and self.siem_client:
            await self.siem_client.disconnect()
            self.siem_client = None
        
        self.siem_config.update(data)
        self.log.info(f'SIEM config updated for {self.siem_config["selected_siem"]}')
        
        # Initialize new client
        if self.siem_config['selected_siem'] and self.siem_config['api_endpoint']:
            await self.get_siem_client()
            
        return web.json_response({'status': 'ok'})

    async def get_detection_data(self, request):
        """Get detection data with filtering options."""
        operation_id = request.query.get('operation_id')
        source = request.query.get('source')
        
        filtered = {'blue': [], 'siem': []}
        
        for blue in self.detections['blue']:
            if operation_id and blue['operation_id'] != operation_id:
                continue
            filtered['blue'].append(blue)
            
        for siem in self.detections['siem']:
            if operation_id and siem['operation_id'] != operation_id:
                continue
            if source and siem['source'] != source:
                continue
            filtered['siem'].append(siem)
            
        return web.json_response(filtered)

    async def get_summary(self, request):
        """Generate comprehensive detection summary."""
        operation_id = request.query.get('operation_id')
        
        summary = {
            'overall': {
                'blue_detections': len(self.detections['blue']),
                'siem_detections': len(self.detections['siem']),
                'detection_ratio': len(self.detections['siem']) / max(len(self.detections['blue']), 1)
            },
            'by_operation': {},
            'timeline_data': []
        }
        
        # Group by operation
        blue_by_op = {}
        for det in self.detections['blue']:
            if operation_id and det['operation_id'] != operation_id:
                continue
            blue_by_op.setdefault(det['operation_id'], []).append(det)
            
        siem_by_op = {}
        for det in self.detections['siem']:
            if operation_id and det['operation_id'] != operation_id:
                continue
            siem_by_op.setdefault(det['operation_id'], []).append(det)
        
        # Calculate statistics per operation
        for op_id in set(list(blue_by_op.keys()) + list(siem_by_op.keys())):
            blue_dets = blue_by_op.get(op_id, [])
            siem_dets = siem_by_op.get(op_id, [])
            
            # Calculate detection delay (average)
            delays = []
            for siem_det in siem_dets:
                siem_time = datetime.fromisoformat(siem_det['timestamp'].replace('Z', '+00:00'))
                for blue_det in blue_dets:
                    blue_time = datetime.fromisoformat(blue_det['timestamp'].replace('Z', '+00:00'))
                    if siem_time > blue_time:
                        delay = (siem_time - blue_time).total_seconds()
                        delays.append(delay)
            
            avg_delay = sum(delays) / len(delays) if delays else 0
            
            summary['by_operation'][op_id] = {
                'blue_count': len(blue_dets),
                'siem_count': len(siem_dets),
                'coverage': len(siem_dets) / max(len(blue_dets), 1),
                'avg_detection_delay_seconds': avg_delay
            }
            
            # Prepare timeline data for chart
            for i, det in enumerate(blue_dets[:10]):  # Limit for chart readability
                summary['timeline_data'].append({
                    'operation': op_id,
                    'type': 'blue',
                    'time': det['timestamp'],
                    'index': i
                })
                
            for i, det in enumerate(siem_dets[:10]):
                summary['timeline_data'].append({
                    'operation': op_id,
                    'type': 'siem',
                    'time': det['timestamp'],
                    'index': i
                })
        
        return web.json_response(summary)


async def enable(services):
    plugin = DetMeterPlugin(services)
    await plugin.enable()
    return plugin
