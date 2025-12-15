"""
DetMeter API Endpoints
Handles HTTP requests and serves the GUI.
"""
import os
from aiohttp import web
import logging

class DetMeterApi:
    def __init__(self, detmeter_svc):
        self.svc = detmeter_svc
        self.log = logging.getLogger('detmeter_api')
        self.static_path = 'plugins/detmeter/static'
    
    async def serve_gui(self, request):
        """Serve the main HTML interface page."""
        try:
            with open(os.path.join(self.static_path, 'detmeter.html'), 'r') as f:
                html_content = f.read()
            return web.Response(text=html_content, content_type='text/html')
        except FileNotFoundError:
            return web.Response(text='<h1>DetMeter GUI not found.</h1>', status=404)
    
    async def serve_static(self, request):
        """Serve static files like JS, CSS."""
        file_path = request.match_info['file_path']
        full_path = os.path.join(self.static_path, file_path)
        if os.path.exists(full_path):
            return web.FileResponse(full_path)
        return web.Response(status=404)
    
    async def analyze_operation(self, request):
        """API endpoint to trigger analysis of an operation."""
        try:
            data = await request.json()
            operation_id = data.get('operation_id')
            if not operation_id:
                return web.json_response({'error': 'Missing operation_id'}, status=400)
            
            report = await self.svc.analyze_operation(operation_id)
            return web.json_response(report)
        except Exception as e:
            self.log.error(f'Analysis error: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    async def get_siem_status(self, request):
        """API endpoint to get the status of configured SIEMs."""
        status = await self.svc.get_siem_status()
        return web.json_response(status)
