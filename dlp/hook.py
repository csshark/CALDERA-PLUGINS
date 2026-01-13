from app.utility.base_world import BaseWorld

name = 'DLP'
description = 'Data Loss Prevention testing with real exfiltration commands'
address = None
access = BaseWorld.Access.RED


async def enable(services):
    app_svc = services.get('app_svc')
