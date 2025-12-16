"""
DetMeter plugin for MITRE Caldera 5.3.0.
Compares Blue agent detection times with real SIEM detections.
"""
import asyncio
import logging
from app.detmeter_svc import DetMeterService
from app.detmeter_gui import DetMeterGUI
from app.detmeter_api_svc import DetMeterApiService

name = 'DetMeter'
description = 'Compare Blue agent detections with SIEM detections'
address = '/plugin/detmeter/gui'

async def enable(services):
    """Entry point for the plugin."""
    # Initialize services
    detmeter_svc = DetMeterService(services)
    detmeter_gui = DetMeterGUI(services)
    detmeter_api = DetMeterApiService(services, detmeter_svc)
    
    # Enable services
    await detmeter_svc.enable()
    await detmeter_gui.enable()
    await detmeter_api.enable()
    
    logging.getLogger('detmeter').info('DetMeter plugin enabled')
    
    return detmeter_svc
