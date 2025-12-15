"""
DetMeter Plugin for MITRE Caldera
Main hook file that initializes the plugin.
"""
from aiohttp import web
import logging

name = 'detmeter'
description = 'Plugin to compare and measure SIEM detection effectiveness'
address = '/plugin/detmeter/gui'

async def enable(services):
    """Main entry point for the plugin, called by Caldera[citation:1]."""
    logging.info('[DetMeter] Enabling DetMeter plugin...')
    app_svc = services.get('app_svc')
    
    # Import our modules
    from plugins.detmeter.detmeter_svc import DetMeterService
    from plugins.detmeter.detmeter_api import DetMeterApi
    
    # Initialize services
    detmeter_svc = DetMeterService(services)
    detmeter_api = DetMeterApi(detmeter_svc)
    
    # Store for potential use by other components
    services['detmeter_svc'] = detmeter_svc
    
    # Register API endpoints
    app = app_svc.application
    app.router.add_route('GET', '/plugin/detmeter/gui', detmeter_api.serve_gui)
    app.router.add_route('POST', '/plugin/detmeter/api/analyze', detmeter_api.analyze_operation)
    app.router.add_route('GET', '/plugin/detmeter/api/status', detmeter_api.get_siem_status)
    app.router.add_route('GET', '/plugin/detmeter/static/{file_path:.+}', detmeter_api.serve_static)
    
    logging.info('[DetMeter] Plugin enabled successfully.')
