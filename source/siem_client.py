import aiohttp
import json
from datetime import datetime, timedelta
from app.utility.base_service import BaseService

class SIEMClient(BaseService):
    
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = self.create_logger('siem_client')
    
    async def get_events_by_time_range(self, start_time, end_time, techniques=None):
        try:
            config = self.get_config('app.detection_validator.siem')
            
            query = self._build_query(start_time, end_time, techniques)
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f'Bearer {config["api_token"]}',
                    'Content-Type': 'application/json'
                }
                
                async with session.post(
                    f"{config['api_endpoint']}/api/search/events",
                    headers=headers,
                    json=query,
                    verify_ssl=config.get('verify_ssl', False),
                    timeout=60
                ) as response:
                    
                    if response.status == 200:
                        events = await response.json()
                        return self._parse_events(events)
                    else:
                        self.log.error(f"SIEM API error: {response.status}")
                        return []
                        
        except Exception as e:
            self.log.error(f"Error fetching SIEM events: {str(e)}")
            return []
    
    def _build_query(self, start_time, end_time, techniques):

        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "deviceReceiptTime": {
                                    "gte": start_iso,
                                    "lte": end_iso
                                }
                            }
                        }
                    ]
                }
            },
            "size": 10000,
            "sort": [{"deviceReceiptTime": "asc"}]
        }
        

        if techniques:
            technique_terms = [{"term": {"mitreTechniqueId": technique}} for technique in techniques]
            query["query"]["bool"]["must"].extend(technique_terms)
        
        return query
    
    def _parse_events(self, raw_events):
        parsed_events = []
        
        for event in raw_events.get('events', []):
            # SIEM has MITRE ATT&CK 
            technique_id = event.get('mitreTechniqueId')
            technique_name = event.get('mitreTechniqueName')
            
            if technique_id:
                parsed_events.append({
                    'timestamp': event.get('deviceReceiptTime'),
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'event_name': event.get('name'),
                    'severity': event.get('severity'),
                    'source_ip': event.get('sourceAddress'),
                    'destination_ip': event.get('destinationAddress'),
                    'raw_event': event
                })
        
        return parsed_events
