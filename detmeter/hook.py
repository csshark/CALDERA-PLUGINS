"""
DetMeter Plugin for MITRE Caldera - Updated for new UI
"""
import logging
import os
from aiohttp import web

name = 'detmeter'
description = 'SIEM Systems Efficiency Validation Plugin'

async def enable(services):
    """Main entry point for the plugin - new Caldera interface"""
    logging.getLogger('detmeter').info('Running...')
    app_svc = services.get('app_svc')
    
    # Import our modules
    try:
        from plugins.detmeter.detmeter_svc import DetMeterService
        from plugins.detmeter.detmeter_api import DetMeterApi
    except ImportError as e:
        logging.error(f'[DetMeter] err importong modules: {e}')
        return
    
    # Initialize services
    try:
        detmeter_svc = DetMeterService(services)
        detmeter_api = DetMeterApi(detmeter_svc, services)
        
        # Store service for other components
        services['detmeter_svc'] = detmeter_svc
        
        # Get the app router
        app = services.get('app_svc').application
        
        # Register API endpoints
        app.router.add_route('GET', '/plugin/detmeter/api/gui', detmeter_api.serve_gui)
        app.router.add_route('GET', '/plugin/detmeter/api/static/{path:.+}', detmeter_api.serve_static)
        app.router.add_route('POST', '/plugin/detmeter/api/analyze', detmeter_api.analyze_operation)
        app.router.add_route('GET', '/plugin/detmeter/api/status', detmeter_api.get_siem_status)
        app.router.add_route('GET', '/plugin/detmeter/api/operations', detmeter_api.get_operations_list)
        
        # Special route for Caldera's new UI system
        app.router.add_route('GET', '/detmeter', detmeter_api.serve_ui_wrapper)
        
        logging.getLogger('detmeter').info('[DetMeter] Plugin został poprawnie wczytany (nowy interfejs)')
        
    except Exception as e:
        logging.error(f'[DetMeter] initializaton error: {e}')
        import traceback
        logging.error(traceback.format_exc())
