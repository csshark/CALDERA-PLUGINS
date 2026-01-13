import logging
from aiohttp import web
from app.utility.base_service import BaseService

class BrowserService(BaseService):
    def __init__(self, services):
        self.services = services
        self.log = logging.getLogger('peek_svc')
        self.navigation_history = {}

    async def get_navigation_targets(self):
        config = self.get_config(name='peek')
        return config.get('urls', {})
