from app.remoteaccess_svc import RemoteAccessService
from app.remoteaccess_api import RemoteAccessApi

name = 'RemoteAccess'
description = 'SSH credential management and remote agent deployment'
address = '/plugin/remoteaccess/gui'

async def initialize(app, services):
    remoteaccess_svc = RemoteAccessService(services)
    await remoteaccess_svc.load_credentials()
    
    remoteaccess_api = RemoteAccessApi(services, remoteaccess_svc)
    
    app.router.add_static('/remoteaccess', 'plugins/remoteaccess/static/', append_version=True)
    app.router.add_route('GET', '/plugin/remoteaccess/gui', remoteaccess_api.landing)
    
    # API routes
    app.router.add_route('*', '/plugin/remoteaccess/credentials', remoteaccess_api.manage_credentials)
    app.router.add_route('*', '/plugin/remoteaccess/deploy', remoteaccess_api.deploy_agent)
    app.router.add_route('*', '/plugin/remoteaccess/remove', remoteaccess_api.remove_agents)
    app.router.add_route('*', '/plugin/remoteaccess/host', remoteaccess_api.manage_host)
    app.router.add_route('GET', '/plugin/remoteaccess/hosts', remoteaccess_api.get_hosts_with_agents)
    app.router.add_route('POST', '/plugin/remoteaccess/test', remoteaccess_api.test_connection)
    app.router.add_route('POST', '/plugin/remoteaccess/command', remoteaccess_api.get_deployment_command)
