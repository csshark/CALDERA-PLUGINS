from aiohttp import web
from app.service.app_svc import AppService
from app.detmeter_api import DetMeterApi

async def setup_plugin(services):
    app_svc = services.get('app_svc')
    data_svc = services.get('data_svc')
    
    detmeter_api = DetMeterApi(services)
    services['detmeter_api'] = detmeter_api
    
    app_svc.add_route('POST', '/plugin/detmeter/validate/{operation_id}', detmeter_api.validate_operation)
    app_svc.add_route('GET', '/plugin/detmeter/results/{operation_id}', detmeter_api.get_results)
    app_svc.add_route('GET', '/plugin/detmeter/gui', detmeter_api.gui)

def main(services):
    services.get('app_svc').register_task(setup_plugin(services))
