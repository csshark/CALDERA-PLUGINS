import logging
from aiohttp import web
from app.service.auth_svc import check_authorization

class DetMeterApiService:

    def __init__(self, plugin_svc):
        self.plugin_svc = plugin_svc
        self.log = logging.getLogger('detmeter')
        
    async def apply(self, app):
        """Apply API routes to the application"""
        # Configuration endpoints
        app.router.add_get('/plugin/detmeter/config', self.get_config)
        app.router.add_post('/plugin/detmeter/config', self.set_config)
        app.router.add_post('/plugin/detmeter/test', self.test_connection)
        
        # Data endpoints
        app.router.add_get('/plugin/detmeter/data', self.get_data)
        app.router.add_get('/plugin/detmeter/summary', self.get_summary)
        app.router.add_get('/plugin/detmeter/operations', self.get_operations)
        app.router.add_post('/plugin/detmeter/clear', self.clear_data)
        
        # Demo endpoints (for testing)
        app.router.add_post('/plugin/detmeter/demo/blue', self.add_demo_blue)
        app.router.add_post('/plugin/detmeter/demo/siem', self.add_demo_siem)
        
    @check_authorization
    async def get_config(self, request):
        """Get current SIEM configuration"""
        try:
            config = await self.plugin_svc.get_config()
            return web.json_response(config)
        except Exception as e:
            self.log.error(f'Error getting config: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def set_config(self, request):
        """Update SIEM configuration"""
        try:
            data = await request.json()
            await self.plugin_svc.update_config(data)
            return web.json_response({'status': 'success'})
        except Exception as e:
            self.log.error(f'Error setting config: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def test_connection(self, request):
        """Test SIEM connection"""
        try:
            data = await request.json()
            result = await self.plugin_svc.test_siem_connection(data)
            return web.json_response(result)
        except Exception as e:
            self.log.error(f'Error testing connection: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_data(self, request):
        """Get detection data"""
        try:
            operation_id = request.query.get('operation_id')
            data = await self.plugin_svc.get_detections(operation_id)
            return web.json_response(data)
        except Exception as e:
            self.log.error(f'Error getting data: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_summary(self, request):
        """Get detection summary"""
        try:
            operation_id = request.query.get('operation_id')
            summary = await self.plugin_svc.get_summary(operation_id)
            return web.json_response(summary)
        except Exception as e:
            self.log.error(f'Error getting summary: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_operations(self, request):
        """Get list of operations"""
        try:
            operations = await self.plugin_svc.get_operations()
            return web.json_response(operations)
        except Exception as e:
            self.log.error(f'Error getting operations: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def clear_data(self, request):
        """Clear detection data"""
        try:
            data = await request.json()
            operation_id = data.get('operation_id')
            await self.plugin_svc.clear_data(operation_id)
            return web.json_response({'status': 'success'})
        except Exception as e:
            self.log.error(f'Error clearing data: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def add_demo_blue(self, request):
        """Add demo blue detection (for testing)"""
        try:
            data = await request.json()
            operation_id = data.get('operation_id', 'demo')
            command = data.get('command', 'whoami')
            
            # Simulate adding a blue detection
            detection = {
                'id': f"demo_blue_{len(self.plugin_svc.detections['blue'])}",
                'operation_id': operation_id,
                'timestamp': '2024-01-01T00:00:00Z',
                'command': command,
                'ability_id': 'demo',
                'agent': 'demo-agent',
                'status': 'success'
            }
            self.plugin_svc.detections['blue'].append(detection)
            
            return web.json_response({'status': 'success', 'detection': detection})
        except Exception as e:
            self.log.error(f'Error adding demo blue: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def add_demo_siem(self, request):
        """Add demo SIEM detection (for testing)"""
        try:
            data = await request.json()
            operation_id = data.get('operation_id', 'demo')
            rule_id = data.get('rule_id', 'DEMO_RULE_001')
            
            detection = {
                'id': f"demo_siem_{len(self.plugin_svc.detections['siem'])}",
                'operation_id': operation_id,
                'timestamp': '2024-01-01T00:01:00Z',
                'rule_id': rule_id,
                'severity': 'high',
                'confidence': 0.8,
                'description': 'Demo SIEM detection',
                'source': 'Demo SIEM'
            }
            self.plugin_svc.detections['siem'].append(detection)
            
            return web.json_response({'status': 'success', 'detection': detection})
        except Exception as e:
            self.log.error(f'Error adding demo siem: {e}')
            return web.json_response({'error': str(e)}, status=500)
