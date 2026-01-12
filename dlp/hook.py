from app.utility.base_plugin import BasePlugin

class DlpPlugin(BasePlugin):
    def __init__(self, services):
        super().__init__(services)
        self.name = 'DLP'
        self.description = 'Data Loss Prevention testing'
        
    async def enable(self):
        self.log.info('DLP plugin loading')
        await self.services.get('data_svc').load_data(self._get_data_dir(), 'abilities')
