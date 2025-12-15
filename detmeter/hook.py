"""
DetMeter Plugin for MITRE Caldera
Main hook file - NEW VERSION without 'address' attribute
"""
import logging
import asyncio
from aiohttp import web

class DetMeterPlugin:
    def __init__(self, services):
        self.name = 'detmeter'
        self.description = 'Plugin do porównywania wykrywalności systemów SIEM'
        self.services = services
        self.data_svc = services.get('data_svc')
        self.app_svc = services.get('app_svc')
        self.log = logging.getLogger('detmeter')
        
        # Initialize services
        self.detmeter_svc = None
        self.detmeter_api = None

    async def enable(self):
        """Enable the plugin - called by Caldera"""
        self.log.info(f'Enabling {self.name} plugin...')
        
        try:
            # Import modules
            from plugins.detmeter.detmeter_svc import DetMeterService
            from plugins.detmeter.detmeter_api import DetMeterApi
            
            # Initialize services
            self.detmeter_svc = DetMeterService(self.services)
            self.detmeter_api = DetMeterApi(self.services, self.detmeter_svc)
            
            # Register service
            self.services.add_service('detmeter_svc', self.detmeter_svc)
            
            # Setup routes
            await self._setup_routes()
            
            # Setup extension
            await self._setup_extension()
            
            self.log.info(f'{self.name} plugin enabled successfully')
            
        except Exception as e:
            self.log.error(f'Failed to enable {self.name} plugin: {str(e)}')
            import traceback
            self.log.error(traceback.format_exc())
            raise

    async def _setup_routes(self):
        """Setup API routes"""
        app = self.app_svc.application
        
        # GUI routes
        app.router.add_route('GET', '/detmeter', self.detmeter_api.gui)
        app.router.add_route('GET', '/detmeter/gui', self.detmeter_api.gui)
        
        # API routes
        app.router.add_route('POST', '/detmeter/api/analyze', self.detmeter_api.analyze_operation)
        app.router.add_route('GET', '/detmeter/api/status', self.detmeter_api.get_siem_status)
        app.router.add_route('GET', '/detmeter/api/operations', self.detmeter_api.get_operations)
        app.router.add_route('GET', '/detmeter/api/techniques', self.detmeter_api.get_techniques)
        app.router.add_route('GET', '/detmeter/api/health', self.detmeter_api.health_check)
        
        # Static files
        app.router.add_route('GET', '/detmeter/static/{path:.*}', self.detmeter_api.serve_static)

    async def _setup_extension(self):
        """Setup Caldera extension"""
        try:
            # Create extension data
            extension_data = {
                'name': self.name,
                'description': self.description,
                'version': '1.0.0',
                'access': ['red', 'blue', 'admin'],
                'data': {
                    'gui': 'detmeter'
                }
            }
            
            # Register with Caldera's extension system if available
            if hasattr(self.app_svc, 'register_extension'):
                self.app_svc.register_extension(extension_data)
                
        except Exception as e:
            self.log.warning(f'Could not register extension: {str(e)}')

    async def help(self):
        """Return help information"""
        return '''
        DetMeter Plugin
        ===============
        A plugin to compare and measure SIEM detection effectiveness.
        
        Endpoints:
        - GET /detmeter              - Main GUI interface
        - POST /detmeter/api/analyze - Analyze operation detection
        - GET /detmeter/api/status   - Check SIEM connectivity
        - GET /detmeter/api/operations - List available operations
        '''


# Caldera plugin entry points
def main(services):
    """Main plugin entry point (legacy)"""
    plugin = DetMeterPlugin(services)
    
    # Schedule enable task
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.create_task(plugin.enable())
    else:
        loop.run_until_complete(plugin.enable())
    
    return plugin


async def setup_plugin(services):
    """Async plugin entry point (new Caldera)"""
    plugin = DetMeterPlugin(services)
    await plugin.enable()
    return plugin


# For direct testing
if __name__ == '__main__':
    print('DetMeter Plugin Module - to be used within MITRE Caldera')
