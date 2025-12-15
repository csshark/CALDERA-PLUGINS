from aiohttp import web
from app.service.base_service import BaseService


class DetMeterApi(BaseService):

    def __init__(self, services, detmeter_svc=None):
        super().__init__(services)
        self.services = services
        self.data_svc = services.get('data_svc')
        self.detmeter_svc = detmeter_svc or services.get('detmeter_svc')
        self.siem_config = self.get_config('app.detmeter.siem')

    async def validate_operation(self, request):
        """Legacy endpoint - redirects to new service"""
        operation_id = request.match_info['operation_id']
        
        if not self.detmeter_svc:
            return web.json_response({'error': 'DetMeter service not available'}, status=500)
        
        report = await self.detmeter_svc.analyze_operation(operation_id)
        return web.json_response(report)

    async def get_results(self, request):
        """Legacy endpoint"""
        operation_id = request.match_info['operation_id']
        return web.json_response({
            'status': 'Use POST /detmeter/validate/{operation_id} endpoint',
            'operation_id': operation_id
        })

    async def gui(self, request):
        """Serve GUI interface"""
        try:
            with open('plugins/detmeter/templates/detmeter.html', 'r') as f:
                html_content = f.read()
            return web.Response(text=html_content, content_type='text/html')
        except FileNotFoundError:
            return web.Response(
                text="<h1>DetMeter Plugin</h1><p>GUI template not found</p>",
                content_type='text/html'
            )
