import logging
from plugins.detmeter.app.detmeter_gui_api import DetMeterApiService

name = 'detmeter'
description = 'Compare Blue agent detections with SIEM detections'
address = '/plugin/detmeter/gui'

async def enable(services):
    """
    Enable the DetMeter plugin
    This is called by Caldera when the plugin is loaded
    """
    plugin_svc = DetMeterService(services)
    await plugin_svc.install()
    return plugin_svc

class DetMeterService:
    """Core service for DetMeter plugin"""
    
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.event_svc = services.get('event_svc')
        self.app_svc = services.get('app_svc')
        self.log = logging.getLogger('detmeter')
        
        # Storage for detections
        self.detections = {
            'blue': [],   # Blue team detections
            'siem': []    # SIEM detections
        }
        
        # SIEM configuration
        self.siem_config = {
            'selected_siem': '',
            'api_endpoint': '',
            'api_key': '',
            'verify_ssl': True,
            'poll_interval': 30
        }
        
        # SIEM clients mapping
        self.siem_clients = {
            'Splunk': self._splunk_client,
            'QRadar': self._qradar_client,
            'Elastic': self._elastic_client
        }
        
    async def install(self):
        """Install plugin routes and event handlers"""
        # Add API routes
        await self._add_api_routes()
        
        # Add GUI route
        await self._add_gui_route()
        
        # Register event handlers
        await self._register_events()
        
        self.log.info('DetMeter plugin installed successfully')
        
    async def _add_api_routes(self):
        """Add API routes to Caldera"""
        api_service = DetMeterApiService(self)
        await api_service.apply(self.app_svc.application)
        
    async def _add_gui_route(self):
        """Add GUI route to Caldera"""
        self.app_svc.application.router.add_route('*', '/plugin/detmeter/gui', self._serve_gui)
        
    async def _serve_gui(self, request):
        """Serve the main GUI page"""
        from aiohttp_jinja2 import template
        from app.service.auth_svc import check_authorization
        
        @check_authorization
        @template('detmeter.html')
        async def _gui(request):
            return {
                'plugin_name': 'DetMeter',
                'plugin_description': self.description,
                'version': '1.0.0'
            }
        
        return await _gui(request)
        
    async def _register_events(self):
        """Register event handlers for Caldera operations"""
        await self.event_svc.observe_event(self._handle_operation_event, exchange='operation')
        
    async def _handle_operation_event(self, event, **kwargs):
        """
        Handle operation events from Caldera
        """
        if event == 'operation/link':
            link = kwargs.get('link')
            if link:
                # Record blue team detection
                await self._record_blue_detection(link)
                # Query SIEM for detections
                await self._query_siem_detections(link)
                
        elif event == 'operation/complete':
            operation = kwargs.get('operation')
            if operation:
                # Final SIEM query for the operation
                await self._final_siem_query(operation.id)
                
    async def _record_blue_detection(self, link):
        """Record a blue team detection"""
        detection = {
            'id': link.id,
            'operation_id': link.operation,
            'timestamp': link.collect.isoformat() if link.collect else None,
            'command': link.command,
            'ability_id': link.ability.ability_id if link.ability else None,
            'agent': link.paw,
            'status': link.status
        }
        self.detections['blue'].append(detection)
        self.log.debug(f'Recorded blue detection: {detection["id"]}')
        
    async def _query_siem_detections(self, link):
        """Query SIEM for detections related to the link"""
        if not self.siem_config['selected_siem']:
            return
            
        siem_client = self.siem_clients.get(self.siem_config['selected_siem'])
        if not siem_client:
            self.log.error(f'No client for SIEM: {self.siem_config["selected_siem"]}')
            return
            
        try:
            # Call the appropriate SIEM client
            siem_detections = await siem_client(link.command, link.operation)
            
            for detection in siem_detections:
                detection['operation_id'] = link.operation
                detection['matched_command'] = link.command[:100]
                detection['source'] = self.siem_config['selected_siem']
                self.detections['siem'].append(detection)
                self.log.info(f'SIEM detection found: {detection.get("rule_id", "unknown")}')
                
        except Exception as e:
            self.log.error(f'SIEM query failed: {e}')
            
    async def _final_siem_query(self, operation_id):
        """Final SIEM query after operation completes"""
        if not self.siem_config['selected_siem']:
            return
            
        # Query for any remaining detections
        self.log.info(f'Final SIEM query for operation {operation_id}')
        
    async def _splunk_client(self, command, operation_id):
        """Splunk SIEM client"""
        # This is a mock implementation
        # In production, implement actual Splunk API calls
        return [{
            'rule_id': 'SPLUNK_DETECTION_001',
            'timestamp': '2024-01-01T00:00:00Z',
            'severity': 'high',
            'confidence': 0.8,
            'description': f'Detected suspicious command: {command[:50]}...'
        }]
        
    async def _qradar_client(self, command, operation_id):
        """QRadar SIEM client"""
        # Mock implementation
        return [{
            'rule_id': 'QRADAR_ALERT_001',
            'timestamp': '2024-01-01T00:00:00Z',
            'severity': 5,
            'confidence': 0.7,
            'description': f'Command execution detected: {command[:50]}...'
        }]
        
    async def _elastic_client(self, command, operation_id):
        """Elastic SIEM client"""
        # Mock implementation
        return [{
            'rule_id': 'ELASTIC_RULE_001',
            'timestamp': '2024-01-01T00:00:00Z',
            'severity': 'medium',
            'confidence': 0.6,
            'description': f'Potential threat detected: {command[:50]}...'
        }]
        
    # Public API methods
    async def get_detections(self, operation_id=None):
        """Get detections with optional filtering"""
        result = {'blue': [], 'siem': []}
        
        for detection in self.detections['blue']:
            if operation_id and detection.get('operation_id') != operation_id:
                continue
            result['blue'].append(detection)
            
        for detection in self.detections['siem']:
            if operation_id and detection.get('operation_id') != operation_id:
                continue
            result['siem'].append(detection)
            
        return result
        
    async def get_summary(self, operation_id=None):
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
            blue_by_op.setdefault(det.get('operation_id', 'unknown'), []).append(det)
            
        siem_by_op = {}
        for det in detections['siem']:
            siem_by_op.setdefault(det.get('operation_id', 'unknown'), []).append(det)
            
        # Calculate per-operation stats
        for op_id in set(list(blue_by_op.keys()) + list(siem_by_op.keys())):
            blue_count = len(blue_by_op.get(op_id, []))
            siem_count = len(siem_by_op.get(op_id, []))
            
            summary['by_operation'][op_id] = {
                'blue_count': blue_count,
                'siem_count': siem_count,
                'coverage': siem_count / max(blue_count, 1) * 100
            }
            
        return summary
        
    async def test_siem_connection(self, config):
        """Test SIEM connection"""
        if not config.get('selected_siem'):
            return {'status': 'error', 'message': 'No SIEM selected'}
            
        if config.get('selected_siem') not in self.siem_clients:
            return {'status': 'error', 'message': f'Unsupported SIEM: {config["selected_siem"]}'}
            
        # Simulate connection test
        await asyncio.sleep(1)
        return {
            'status': 'success',
            'message': f'Successfully connected to {config["selected_siem"]}'
        }
        
    async def update_config(self, config):
        """Update SIEM configuration"""
        self.siem_config.update(config)
        self.log.info(f'SIEM config updated: {config}')
        
    async def get_config(self):
        """Get current configuration"""
        return self.siem_config
        
    async def get_operations(self):
        """Get list of operations"""
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
        
    async def clear_data(self, operation_id=None):
        """Clear detection data"""
        if operation_id:
            self.detections['blue'] = [d for d in self.detections['blue'] if d.get('operation_id') != operation_id]
            self.detections['siem'] = [d for d in self.detections['siem'] if d.get('operation_id') != operation_id]
        else:
            self.detections = {'blue': [], 'siem': []}
        self.log.info(f'Cleared detection data')
