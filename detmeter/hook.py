"""
DetMeter Plugin for MITRE Caldera
Simplified hook that works with Caldera's plugin system
"""
import os
import logging
from aiohttp import web

# Configure logger
logger = logging.getLogger('detmeter')

# Plugin metadata - CALDERA EXPECTS THESE AT MODULE LEVEL
name = 'detmeter'
description = 'SIEM Detection Comparison Plugin'

async def enable(services):
    """
    Main plugin entry point - Caldera calls this function
    """
    logger.info('[DetMeter] Enabling plugin...')
    
    try:
        # Import our service
        from plugins.detmeter.detmeter_svc import DetMeterService
        
        # Initialize service
        detmeter_svc = DetMeterService(services)
        services['detmeter_svc'] = detmeter_svc
        
        # Get app service
        app_svc = services.get('app_svc')
        app = app_svc.application
        
        # Setup API routes
        setup_routes(app, detmeter_svc)
        
        logger.info('[DetMeter] Plugin enabled successfully')
        return True
        
    except Exception as e:
        logger.error(f'[DetMeter] Failed to enable plugin: {str(e)}')
        import traceback
        logger.error(traceback.format_exc())
        return False

def setup_routes(app, detmeter_svc):
    """Setup all routes for the plugin"""
    
    # Main GUI page
    async def gui_handler(request):
        """Serve the main HTML interface"""
        try:
            # Read HTML template
            template_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
            with open(template_path, 'r', encoding='utf-8') as f:
                html = f.read()
            return web.Response(text=html, content_type='text/html')
        except FileNotFoundError:
            # Fallback HTML
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>DetMeter</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                .container { max-width: 800px; margin: auto; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .card { background: #f8f9fa; padding: 20px; margin: 20px 0; }
                input, button { padding: 10px; margin: 5px; }
                button { background: #3498db; color: white; border: none; }
            </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h1>DetMeter Plugin</h1></div>
                    <div class="card">
                        <h3>Plugin is installed but template file is missing.</h3>
                        <p>Check plugins/detmeter/templates/index.html</p>
                    </div>
                </div>
            </body>
            </html>
            """
            return web.Response(text=html, content_type='text/html')
    
    # API: Analyze operation
    async def analyze_handler(request):
        """Analyze operation detection"""
        try:
            data = await request.json()
            operation_id = data.get('operation_id')
            
            if not operation_id:
                return web.json_response({'error': 'operation_id required'}, status=400)
            
            # Import here to avoid circular imports
            from plugins.detmeter.detmeter_svc import DetMeterService
            
            # Get service from request if not passed
            svc = detmeter_svc or request.app['services'].get('detmeter_svc')
            if not svc:
                return web.json_response({'error': 'Service not available'}, status=500)
            
            result = await svc.analyze_operation(operation_id)
            return web.json_response(result)
            
        except Exception as e:
            logger.error(f'Analyze error: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    # API: Get SIEM status
    async def status_handler(request):
        """Get SIEM connection status"""
        try:
            from plugins.detmeter.detmeter_svc import DetMeterService
            
            svc = detmeter_svc or request.app['services'].get('detmeter_svc')
            if not svc:
                return web.json_response({'error': 'Service not available'}, status=500)
            
            status = await svc.get_siem_status()
            return web.json_response(status)
            
        except Exception as e:
            logger.error(f'Status error: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    # API: List operations
    async def operations_handler(request):
        """List available operations"""
        try:
            data_svc = request.app['services'].get('data_svc')
            if not data_svc:
                return web.json_response({'error': 'Data service not available'}, status=500)
            
            operations = await data_svc.locate('operations')
            formatted = []
            
            for op in operations:
                if hasattr(op, 'id'):
                    formatted.append({
                        'id': op.id,
                        'name': getattr(op, 'name', 'Unnamed'),
                        'start': getattr(op, 'start', None),
                        'state': getattr(op, 'state', 'unknown')
                    })
            
            return web.json_response(formatted)
            
        except Exception as e:
            logger.error(f'Operations error: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    # API: Health check
    async def health_handler(request):
        """Health check endpoint"""
        return web.json_response({
            'status': 'ok',
            'plugin': 'detmeter',
            'version': '1.0.0'
        })
    
    # Register routes
    app.router.add_get('/detmeter', gui_handler)
    app.router.add_get('/detmeter/gui', gui_handler)
    app.router.add_post('/detmeter/api/analyze', analyze_handler)
    app.router.add_get('/detmeter/api/status', status_handler)
    app.router.add_get('/detmeter/api/operations', operations_handler)
    app.router.add_get('/detmeter/api/health', health_handler)
    
    logger.info('[DetMeter] Routes registered')
