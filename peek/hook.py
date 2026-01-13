from app.utility.base_world import BaseWorld

name = 'Browser Dashboard'
description = 'Embedded browser with navigation controls and operation status'
address = '/plugin/peek/gui'
access = BaseWorld.Access.RED


async def enable(services):
    app = services.get('app_svc').application
    browser_gui = BrowserGui(services)
    
    app.router.add_static('/browser_static', 'plugins/browser_dashboard/static/', append_version=True)
    app.router.add_route('GET', '/plugin/peek/gui', browser_gui.splash)
    app.router.add_route('GET', '/plugin/peek/current_operation', browser_gui.current_operation)
    app.router.add_route('POST', '/plugin/peek/navigate', browser_gui.navigate)


class BrowserGui:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.config = BaseWorld.apply_config('browser_dashboard', 
                                           BaseWorld.strip_yml('plugins/peek/conf/default.yml')[0])

    async def splash(self, request):
        with open('plugins/peek/templates/browser.html', 'r') as f:
            content = f.read()
        return web.Response(text=content, content_type='text/html')

    async def current_operation(self, request):
        operations = await self.data_svc.locate('operations', match=dict(state='running'))
        if operations:
            op = operations[0]
            return web.json_response({
                'id': op.id,
                'name': op.name,
                'state': op.state,
                'start': op.created.strftime('%Y-%m-%d %H:%M:%S') if op.created else '',
                'agents': len(op.agents)
            })
        return web.json_response({'name': 'No active operation', 'state': 'idle'})

    async def navigate(self, request):
        data = await request.json()
        target = data.get('target', 'home')
        
        urls = self.config.get('urls', {})
        url = urls.get(target, urls.get('home', 'https://www.google.com'))
        
        return web.json_response({'url': url, 'target': target})
