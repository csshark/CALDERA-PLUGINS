from aiohttp import web
import json

class RemoteAccessApi:
    def __init__(self, services, remoteaccess_svc):
        self.services = services
        self.remoteaccess_svc = remoteaccess_svc
        self.auth_svc = services.get('auth_svc')

    async def landing(self, request):
        return web.FileResponse('plugins/remoteaccess/templates/remoteaccess.html')

    async def manage_credentials(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        
        if request.method == 'GET':
            return web.json_response(self.remoteaccess_svc.credentials)
        
        elif request.method == 'POST':
            data = await request.json()
            await self.remoteaccess_svc.add_credential(
                data['host'],
                data['username'],
                data.get('password'),
                data.get('key_file'),
                data.get('port', 22)
            )
            return web.json_response({'status': 'success'})
        
        elif request.method == 'DELETE':
            data = await request.json()
            await self.remoteaccess_svc.remove_credential(data['host'])
            return web.json_response({'status': 'success'})

    async def deploy_agent(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        data = await request.json()
        
        if data['agent_type'] == 'blue':
            result = await self.remoteaccess_svc.deploy_blue_agent(data['host'], data.get('platform', 'linux'))
        else:
            result = await self.remoteaccess_svc.deploy_red_agent(data['host'], data.get('platform', 'linux'))
        
        return web.json_response(result)

    async def remove_agents(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        data = await request.json()
        result = await self.remoteaccess_svc.remove_agents(data['host'])
        return web.json_response(result)

    async def manage_host(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        data = await request.json()
        
        if data['action'] == 'shutdown':
            result = await self.remoteaccess_svc.shutdown_host(data['host'])
        elif data['action'] == 'info':
            result = await self.remoteaccess_svc.get_system_info(data['host'])
        else:
            result = {'error': 'Unknown action'}
        
        return web.json_response(result)

    async def get_hosts_with_agents(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        hosts = await self.remoteaccess_svc.get_hosts_with_agents()
        return web.json_response(hosts)

    async def test_connection(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        data = await request.json()
        result = await self.remoteaccess_svc.test_connection(data['host'])
        return web.json_response(result)

    async def get_deployment_command(self, request):
        await self.auth_svc.check_permissions(request, 'app')
        data = await request.json()
        
        platform = data.get('platform', 'windows')
        agent_type = data.get('agent_type', 'red')
        
        command = self.remoteaccess_svc.get_deployment_command(agent_type, platform)
        return web.json_response({'command': command})
