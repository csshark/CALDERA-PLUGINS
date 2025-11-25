import asyncio
from datetime import datetime, timedelta
from app.utility.base_service import BaseService

class DetectionValidator(BaseService):
    
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.siem_client = None
        self.log = self.create_logger('detection_validator')
    
    async def validate_operation_detection(self, operation_id):
        """Główna funkcja walidująca detekcję operacji"""
        try:
            # get caldera operation details 
            operation = await self._get_operation_data(operation_id)
            if not operation:
                return None
            
            # mitre techniques 
            used_techniques = await self._extract_used_techniques(operation)
            
            # get SIEM events from operation time
            siem_events = await self.siem_client.get_events_by_time_range(
                operation['start_time'],
                operation['end_time'] or datetime.now(),
                used_techniques
            )
            
            #compare + gen raport 
            report = await self._generate_detection_report(
                operation, 
                used_techniques, 
                siem_events
            )
            
            return report
            
        except Exception as e:
            self.log.error(f"Validation error: {str(e)}")
            return None
    # this is problematic pls work now 
    async def _get_operation_data(self, operation_id):
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        if not operations:
            return None
        
        op = operations[0]
        return {
            'id': op.id,
            'name': op.name,
            'adversary': op.adversary.name if op.adversary else 'Unknown',
            'start_time': op.start,
            'end_time': op.finish,
            'chain': op.chain
        }
    
    async def _extract_used_techniques(self, operation):
        techniques = set()
        
        for link in operation['chain']:
            if hasattr(link, 'ability') and link.ability:
                technique_id = link.ability.technique_id
                if technique_id and technique_id.startswith('T'):
                    techniques.add(technique_id)
        
        return list(techniques)
    
    async def _generate_detection_report(self, operation, used_techniques, siem_events):
        # group SIEM events by techniques 
        detected_techniques = {}
        for event in siem_events:
            technique = event['technique_id']
            if technique not in detected_techniques:
                detected_techniques[technique] = []
            detected_techniques[technique].append(event)
        
        # compare techniques
        detection_analysis = {}
        for technique in used_techniques:
            detected = technique in detected_techniques
            detection_analysis[technique] = {
                'used': True,
                'detected': detected,
                'detection_count': len(detected_techniques.get(technique, [])),
                'events': detected_techniques.get(technique, [])
            }
        
        # process statistics 
        total_techniques = len(used_techniques)
        detected_techniques_count = len([t for t in used_techniques if t in detected_techniques])
        detection_rate = (detected_techniques_count / total_techniques * 100) if total_techniques > 0 else 0
        
        return {
            'operation': {
                'id': operation['id'],
                'name': operation['name'],
                'adversary': operation['adversary'],
                'start_time': operation['start_time'].isoformat(),
                'end_time': operation['end_time'].isoformat() if operation['end_time'] else None
            },
            'statistics': {
                'total_techniques_used': total_techniques,
                'techniques_detected': detected_techniques_count,
                'detection_rate': round(detection_rate, 2),
                'total_siem_events': len(siem_events)
            },
            'technique_analysis': detection_analysis,
            'used_techniques': used_techniques,
            'detected_techniques': list(detected_techniques.keys()),
            'report_generated': datetime.now().isoformat()
        }
