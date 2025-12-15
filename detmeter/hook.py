"""
MITRE Caldera DetMeter Plugin Hook
Integrates detection analysis capabilities into Caldera
"""
import asyncio
import logging
from aiohttp import web

from plugins.detmeter.detmeter_api import DetMeterApi
from plugins.detmeter.detmeter_svc import DetMeterService


class DetMeterPlugin:
    """Main plugin class for DetMeter integration"""

    def __init__(self, services, name='detmeter'):
        self.name = name
        self.services = services
        self.data_svc = services.get('data_svc')
        self.app_svc = services.get('app_svc')
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('detmeter_plugin')
        
        # Initialize services
        self.detmeter_svc = None
        self.detmeter_api = None

    async def enable(self):
        """Enable the plugin - called by Caldera on startup"""
        try:
            self.log.info("Enabling DetMeter plugin...")
            
            # Initialize services
            self.detmeter_svc = DetMeterService(self.services)
            self.detmeter_api = DetMeterApi(self.services, self.detmeter_svc)
            
            # Register service for other plugins/components
            self.services.add_service('detmeter_svc', self.detmeter_svc)
            
            # Register API endpoints
            await self._setup_routes()
            
            # Register periodic tasks (optional)
            await self._setup_tasks()
            
            # Register GUI extension
            await self._setup_gui()
            
            self.log.info("DetMeter plugin enabled successfully")
            
        except Exception as e:
            self.log.error(f"Failed to enable DetMeter plugin: {str(e)}")
            raise

    async def _setup_routes(self):
        """Setup all API routes for the plugin"""
        
        # Public endpoints (no authentication required for testing)
        self.app_svc.add_route('GET', '/detmeter/gui', self.detmeter_api.gui)
        self.app_svc.add_route('GET', '/detmeter/status', self.get_siem_status)
        
        # Operation analysis endpoints
        self.app_svc.add_route('POST', '/detmeter/validate/{operation_id}', 
                              self.validate_operation)
        self.app_svc.add_route('GET', '/detmeter/results/{operation_id}', 
                              self.get_operation_results)
        self.app_svc.add_route('GET', '/detmeter/coverage/{operation_id}', 
                              self.get_technique_coverage)
        
        # Simulation endpoints
        self.app_svc.add_route('POST', '/detmeter/simulate', 
                              self.simulate_detection)
        self.app_svc.add_route('POST', '/detmeter/simulate/{technique_ids}', 
                              self.simulate_techniques)
        
        # Configuration endpoints (protected)
        self.app_svc.add_route('POST', '/detmeter/config/siem', 
                              self.update_siem_config)
        self.app_svc.add_route('GET', '/detmeter/config', 
                              self.get_config)
        
        # Health check
        self.app_svc.add_route('GET', '/detmeter/health', self.health_check)

    async def _setup_tasks(self):
        """Setup periodic background tasks"""
        # Example: Daily detection rate report
        async def daily_report():
            while True:
                await asyncio.sleep(86400)  # 24 hours
                await self._generate_daily_report()
        
        # Example: SIEM connectivity monitoring
        async def siem_monitor():
            while True:
                await asyncio.sleep(300)  # 5 minutes
                await self._check_siem_health()
        
        # Uncomment to enable periodic tasks
        # asyncio.create_task(daily_report())
        # asyncio.create_task(siem_monitor())

    async def _setup_gui(self):
        """Register GUI components with Caldera"""
        try:
            # Add plugin to Caldera's GUI menu
            plugin_data = {
                'name': self.name,
                'description': 'Detection effectiveness analyzer',
                'version': '1.0.0',
                'routes': [
                    {'path': '/detmeter/gui', 'name': 'DetMeter Dashboard'},
                    {'path': '/detmeter/config', 'name': 'SIEM Configuration'}
                ]
            }
            
            # Use Caldera's extension system if available
            if hasattr(self.app_svc, 'add_plugin_extension'):
                self.app_svc.add_plugin_extension(plugin_data)
            
            self.log.debug("GUI extensions registered")
            
        except Exception as e:
            self.log.warning(f"Could not register GUI extensions: {str(e)}")

    # API Endpoint Handlers

    async def validate_operation(self, request):
        """Validate operation detection rate"""
        try:
            operation_id = request.match_info.get('operation_id')
            if not operation_id:
                return web.json_response({'error': 'Operation ID required'}, status=400)
            
            # Check if operation exists
            operations = await self.data_svc.locate('operations', dict(id=operation_id))
            if not operations:
                return web.json_response({'error': 'Operation not found'}, status=404)
            
            # Generate detection report
            report = await self.detmeter_svc.analyze_operation(operation_id)
            
            if 'error' in report:
                return web.json_response(report, status=400)
            
            return web.json_response(report)
            
        except Exception as e:
            self.log.error(f"Error validating operation: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_operation_results(self, request):
        """Get cached results for an operation"""
        try:
            operation_id = request.match_info.get('operation_id')
            if not operation_id:
                return web.json_response({'error': 'Operation ID required'}, status=400)
            
            # Try to get cached report
            cached = await self.detmeter_svc.get_cached_report(operation_id)
            if cached:
                return web.json_response(cached)
            
            # If not cached, generate new report
            return await self.validate_operation(request)
            
        except Exception as e:
            self.log.error(f"Error getting operation results: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_technique_coverage(self, request):
        """Get detailed technique coverage analysis"""
        try:
            operation_id = request.match_info.get('operation_id')
            if not operation_id:
                return web.json_response({'error': 'Operation ID required'}, status=400)
            
            # Check if operation exists
            operations = await self.data_svc.locate('operations', dict(id=operation_id))
            if not operations:
                return web.json_response({'error': 'Operation not found'}, status=404)
            
            # Get technique coverage analysis
            coverage = await self.detmeter_svc.get_technique_coverage(operation_id)
            
            return web.json_response(coverage)
            
        except Exception as e:
            self.log.error(f"Error getting technique coverage: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_siem_status(self, request):
        """Get SIEM connectivity status"""
        try:
            status = await self.detmeter_svc.get_siem_status()
            return web.json_response(status)
            
        except Exception as e:
            self.log.error(f"Error getting SIEM status: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def simulate_detection(self, request):
        """Simulate detection for specific techniques"""
        try:
            data = await request.json()
            technique_ids = data.get('technique_ids', [])
            timeframe_hours = data.get('timeframe_hours', 24)
            
            if not technique_ids:
                return web.json_response({'error': 'technique_ids required'}, status=400)
            
            simulation = await self.detmeter_svc.simulate_detection(
                technique_ids, 
                timeframe_hours
            )
            
            return web.json_response(simulation)
            
        except Exception as e:
            self.log.error(f"Error simulating detection: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def simulate_techniques(self, request):
        """Simulate detection for techniques from URL path"""
        try:
            technique_ids_str = request.match_info.get('technique_ids', '')
            technique_ids = [t.strip() for t in technique_ids_str.split(',') if t.strip()]
            
            if not technique_ids:
                return web.json_response({'error': 'No techniques specified'}, status=400)
            
            # Optional timeframe from query parameter
            timeframe_hours = int(request.query.get('hours', 24))
            
            simulation = await self.detmeter_svc.simulate_detection(
                technique_ids, 
                timeframe_hours
            )
            
            return web.json_response(simulation)
            
        except Exception as e:
            self.log.error(f"Error simulating techniques: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def update_siem_config(self, request):
        """Update SIEM configuration"""
        try:
            data = await request.json()
            
            # Validate required fields
            siem_type = data.get('type')
            endpoint = data.get('api_endpoint')
            token = data.get('api_token')
            
            if not siem_type:
                return web.json_response({'error': 'SIEM type required'}, status=400)
            
            # In a real implementation, you would save this to a config file or database
            # For now, we'll just update the service's config
            self.detmeter_svc.siem_config.update(data)
            
            return web.json_response({
                'status': 'updated',
                'config': self.detmeter_svc.siem_config
            })
            
        except Exception as e:
            self.log.error(f"Error updating SIEM config: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_config(self, request):
        """Get current SIEM configuration"""
        try:
            # Don't return the actual token for security
            safe_config = self.detmeter_svc.siem_config.copy()
            if 'api_token' in safe_config:
                safe_config['api_token'] = '***' if safe_config['api_token'] else None
            
            return web.json_response({
                'config': safe_config,
                'supported_siem_types': list(self.detmeter_svc.siem_adapters.keys())
            })
            
        except Exception as e:
            self.log.error(f"Error getting config: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def health_check(self, request):
        """Health check endpoint"""
        try:
            # Check service dependencies
            svc_status = {
                'detmeter_svc': self.detmeter_svc is not None,
                'data_svc': self.data_svc is not None,
                'app_svc': self.app_svc is not None
            }
            
            # Check SIEM connectivity
            siem_status = await self.detmeter_svc.get_siem_status()
            
            return web.json_response({
                'status': 'healthy',
                'plugin': self.name,
                'version': '1.0.0',
                'services': svc_status,
                'siem': siem_status,
                'timestamp': asyncio.get_event_loop().time()
            })
            
        except Exception as e:
            self.log.error(f"Health check failed: {str(e)}")
            return web.json_response({
                'status': 'unhealthy',
                'error': str(e)
            }, status=500)

    # Internal helper methods

    async def _generate_daily_report(self):
        """Generate daily detection rate report"""
        try:
            # Get all operations from last 24 hours
            # Implementation depends on your Caldera setup
            pass
            
        except Exception as e:
            self.log.error(f"Error generating daily report: {str(e)}")

    async def _check_siem_health(self):
        """Periodic SIEM health check"""
        try:
            status = await self.detmeter_svc.get_siem_status()
            if status.get('status') != 'connected':
                self.log.warning(f"SIEM connectivity issue: {status.get('message')}")
                
        except Exception as e:
            self.log.error(f"SIEM health check failed: {str(e)}")


# Caldera plugin entry point
def main(services):
    """
    Entry point for Caldera plugin system
    This function is called by Caldera on startup
    """
    plugin = DetMeterPlugin(services)
    
    # Register setup task
    app_svc = services.get('app_svc')
    if app_svc and hasattr(app_svc, 'register_task'):
        app_svc.register_task(plugin.enable())
    else:
        # Fallback for older Caldera versions
        asyncio.create_task(plugin.enable())
    
    return plugin


# Alternative entry point for newer Caldera versions
async def setup_plugin(services):
    """
    Alternative async entry point for Caldera >= 4.0
    """
    plugin = DetMeterPlugin(services)
    await plugin.enable()
    return plugin


# For direct testing
if __name__ == '__main__':
    print("DetMeter Plugin Module")
    print("This plugin is designed to run within MITRE Caldera")
    print("Install in plugins/detmeter/ directory")
