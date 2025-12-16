"""
API service for DetMeter plugin.
Handles REST API endpoints.
"""
import logging
from aiohttp import web
from app.service.auth_svc import check_authorization

class DetMeterApiService:
    """API service for DetMeter plugin"""
    
    def __init__(self, services, detmeter_svc):
        self.services = services
        self.detmeter_svc = detmeter_svc
        self.app_svc = services.get('app_svc')
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('detmeter')
        
    async def enable(self):
        """Enable API routes"""
        app = self.app_svc.application
        
        # Configuration endpoints
        app.router.add_route('GET', '/plugin/detmeter/config', self.get_config)
        app.router.add_route('POST', '/plugin/detmeter/config', self.set_config)
        app.router.add_route('POST', '/plugin/detmeter/test', self.test_connection)
        
        # Data endpoints
        app.router.add_route('GET', '/plugin/detmeter/data', self.get_data)
        app.router.add_route('GET', '/plugin/detmeter/summary', self.get_summary)
        app.router.add_route('GET', '/plugin/detmeter/operations', self.get_operations)
        app.router.add_route('POST', '/plugin/detmeter/clear', self.clear_data)
        
        self.log.info('DetMeter API enabled')
        
    @check_authorization
    async def get_config(self, request):
        """Get current SIEM configuration"""
        try:
            config = await self.detmeter_svc.get_config()
            return web.json_response(config)
        except Exception as e:
            self.log.error(f'Error getting config: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def set_config(self, request):
        """Update SIEM configuration"""
        try:
            data = await request.json()
            await self.detmeter_svc.update_config(data)
            return web.json_response({'status': 'success'})
        except Exception as e:
            self.log.error(f'Error setting config: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def test_connection(self, request):
        """Test SIEM connection"""
        try:
            data = await request.json()
            result = await self.detmeter_svc.test_siem_connection(data)
            return web.json_response(result)
        except Exception as e:
            self.log.error(f'Error testing connection: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_data(self, request):
        """Get detection data"""
        try:
            operation_id = request.query.get('operation_id')
            data = await self.detmeter_svc.get_detections(operation_id)
            return web.json_response(data)
        except Exception as e:
            self.log.error(f'Error getting data: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_summary(self, request):
        """Get detection summary"""
        try:
            operation_id = request.query.get('operation_id')
            summary = await self.detmeter_svc.get_summary(operation_id)
            return web.json_response(summary)
        except Exception as e:
            self.log.error(f'Error getting summary: {e}')
            return web.json_response({'error': str(e)}, status=500)
            
    @check_authorization
    async def get_operations(self, request):
        """Get list of operations"""
        try:
            operations = await self.detmeter_svc.get_operations()
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
            await self.detmeter_svc.clear_data(operation_id)
            return web.json_response({'status': 'success'})
        except Exception as e:
            self.log.error(f'Error clearing data: {e}')
            return web.json_response({'error': str(e)}, status=500)
