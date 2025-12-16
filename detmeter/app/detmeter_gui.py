"""
GUI service for DetMeter plugin.
Handles web interface and templates.
"""
import logging
from aiohttp import web
from aiohttp_jinja2 import template
from app.service.auth_svc import check_authorization

class DetMeterGUI:
    """GUI service for DetMeter plugin"""
    
    def __init__(self, services):
        self.services = services
        self.app_svc = services.get('app_svc')
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('detmeter')
        
    async def enable(self):
        """Enable GUI routes"""
        app = self.app_svc.application
        
        # Main GUI route
        app.router.add_route('*', '/plugin/detmeter/gui', self.splash)
        
        # Static files (if needed)
        # app.router.add_static('/static/detmeter', 'plugins/detmeter/static')
        
        self.log.info('DetMeter GUI enabled')
        
    @check_authorization
    @template('detmeter.html')
    async def splash(self, request):
        """Main GUI page"""
        return {
            'plugin_name': 'DetMeter',
            'plugin_description': 'Compare Blue agent detections with SIEM detections',
            'version': '1.0.0'
        }
