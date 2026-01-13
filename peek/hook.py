from app.utility.base_world import BaseWorld
from aiohttp import web

name = 'Peek'
description = 'Embedded browser dashboard for security tools'
address = '/plugin/peek/gui'
access = BaseWorld.Access.RED


async def enable(services):
    app = services.get('app_svc').application
    peek_gui = PeekGui(services)
    
    app.router.add_static('/peek_static', 'plugins/peek/static/', append_version=True)
    app.router.add_route('GET', '/plugin/peek/gui', peek_gui.splash)
    app.router.add_route('GET', '/plugin/peek/operation', peek_gui.current_operation)


class PeekGui:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.config = BaseWorld.apply_config('peek', 
                                           BaseWorld.strip_yml('plugins/peek/conf/default.yml')[0])

    async def splash(self, request):
        with open('plugins/peek/templates/peek.html', 'r') as f:
            content = f.read()
        return web.Response(text=content, content_type='text/html')

    async def current_operation(self, request):
        operations = await self.data_svc.locate('operations', match=dict(state='running'))
        if operations:
            op = operations[0]
            return web.json_response({
                'name': op.name,
                'state': op.state,
                'start': op.created.strftime('%Y-%m-%d %H:%M:%S') if op.created else '',
                'agents': len(op.agents)
            })
        return web.json_response({'name': 'No active operation', 'state': 'idle'})
