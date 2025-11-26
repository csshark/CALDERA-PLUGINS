from aiohttp import web
from app.service.base_service import BaseService
from app.utility.base_planning_svc import BasePlanningService

class DetMeterApi(BaseService):

    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.siem_config = self.get_config('app.detmeter.siem')

    async def validate_operation(self, request):
        operation_id = request.match_info['operation_id']
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        
        if not operations:
            return web.json_response({'error': 'Operation not found'}, status=404)
        
        op = operations[0]
        report = await self._generate_detection_report(op)
        
        return web.json_response(report)

    async def get_results(self, request):
        operation_id = request.match_info['operation_id']
        return web.json_response({'status': 'Use POST /validate endpoint'})

    async def gui(self, request):
        with open('plugins/detmeter/templates/detmeter.html', 'r') as f:
            html_content = f.read()
        return web.Response(text=html_content, content_type='text/html')

    async def _generate_detection_report(self, operation):
        techniques_used = await self._extract_techniques(operation)
        siem_events = await self._fetch_siem_events(operation.start, operation.finish, techniques_used)
        
        detected_techniques = set(event['technique_id'] for event in siem_events)
        
        return {
            'operation_id': operation.id,
            'operation_name': operation.name,
            'techniques_used': techniques_used,
            'techniques_detected': list(detected_techniques),
            'detection_rate': len(detected_techniques) / len(techniques_used) * 100 if techniques_used else 0,
            'siem_events_count': len(siem_events),
            'siem_type': self.siem_config.get('type', 'arcsight')  # flexible
        }

    async def _extract_techniques(self, operation):
        techniques = set()
        for link in operation.chain:
            if hasattr(link, 'ability') and link.ability and link.ability.technique_id:
                techniques.add(link.ability.technique_id)
        return list(techniques)

    async def _fetch_siem_events(self, start_time, end_time, techniques):
        siem_type = self.siem_config.get('type', 'arcsight')  # flexible
        api_endpoint = self.siem_config.get('api_endpoint', 'https://localhost:8443')  # flexible
        api_token = self.siem_config.get('api_token', 'default_token')  # flexible
        
        if siem_type == 'arcsight':
            return await self._fetch_arcsight_events(start_time, end_time, techniques, api_endpoint, api_token)
        elif siem_type == 'splunk':
            return await self._fetch_splunk_events(start_time, end_time, techniques, api_endpoint, api_token)
        return []

    async def _fetch_arcsight_events(self, start_time, end_time, techniques, endpoint, token):
        import aiohttp
        headers = {'Authorization': f'Bearer {token}'}  # flexible auth method
        query = {
            "startTime": start_time.isoformat(),
            "endTime": end_time.isoformat() if end_time else start_time.isoformat(),
            "techniques": techniques
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{endpoint}/api/search", headers=headers, json=query) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('events', [])
        except Exception:
            pass
        return []

    async def _fetch_splunk_events(self, start_time, end_time, techniques, endpoint, token):
        return []
