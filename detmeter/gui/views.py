from aiohttp import web
from app.service.base_service import BaseService

class DetMeterGUI(BaseService):

    def __init__(self, services):
        self.services = services

    async def get_detmeter_page(self, request):
        return web.Response(text='DetMeter GUI', content_type='text/html')
