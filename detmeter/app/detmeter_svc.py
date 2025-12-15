"""
Service layer for DetMeter plugin - handles SIEM integration and detection analysis
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from aiohttp import ClientSession, ClientTimeout
import asyncio

from app.service.base_service import BaseService
from app.utility.base_world import BaseWorld


class DetMeterService(BaseService):
    """Service for SIEM integration and detection rate analysis"""

    def __init__(self, services):
        super().__init__(services)
        self.services = services
        self.data_svc = services.get('data_svc')
        self.planning_svc = services.get('planning_svc')
        self.log = logging.getLogger('detmeter_svc')
        
        # Load configuration
        self.siem_config = self.get_config('app.detmeter.siem')
        self.cache = {}  # Simple cache for SIEM results
        self.cache_ttl = timedelta(minutes=5)
        
        # Supported SIEM types and their adapters
        self.siem_adapters = {
            'arcsight': self._query_arcsight,
            'splunk': self._query_splunk,
            'qradar': self._query_qradar,
            'elastic': self._query_elastic,
            'test': self._query_test_mode  # For testing without real SIEM
        }

    async def analyze_operation(self, operation_id: str) -> Dict[str, Any]:
        """
        Main analysis method for an operation
        Returns comprehensive detection report
        """
        try:
            # Get operation data
            operations = await self.data_svc.locate('operations', dict(id=operation_id))
            if not operations:
                return {'error': 'Operation not found', 'operation_id': operation_id}
            
            operation = operations[0]
            
            # Extract MITRE techniques from operation
            techniques_used = await self._extract_techniques(operation)
            if not techniques_used:
                return {'error': 'No MITRE techniques found in operation', 'operation_id': operation_id}
            
            # Fetch SIEM events for the operation timeframe
            siem_events = await self._fetch_siem_events(
                operation.start,
                operation.finish or datetime.now(),
                techniques_used
            )
            
            # Analyze detection coverage
            analysis = await self._analyze_detection_coverage(techniques_used, siem_events, operation)
            
            # Generate report
            report = await self._generate_detection_report(operation, techniques_used, siem_events, analysis)
            
            # Cache results
            self._cache_results(operation_id, report)
            
            return report
            
        except Exception as e:
            self.log.error(f"Error analyzing operation {operation_id}: {str(e)}")
            return {'error': str(e), 'operation_id': operation_id}

    async def get_technique_coverage(self, operation_id: str) -> Dict[str, Any]:
        """
        Get detailed technique-by-technique coverage analysis
        """
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        if not operations:
            return {'error': 'Operation not found'}
        
        operation = operations[0]
        techniques_used = await self._extract_techniques(operation)
        
        coverage_analysis = {}
        for technique in techniques_used:
            technique_events = await self._fetch_events_for_technique(
                operation.start,
                operation.finish or datetime.now(),
                technique
            )
            
            coverage_analysis[technique] = {
                'events_count': len(technique_events),
                'detected': len(technique_events) > 0,
                'event_samples': technique_events[:5],  # First 5 events
                'first_detection': technique_events[0]['timestamp'] if technique_events else None,
                'last_detection': technique_events[-1]['timestamp'] if technique_events else None
            }
        
        return {
            'operation_id': operation_id,
            'technique_coverage': coverage_analysis,
            'total_techniques': len(techniques_used),
            'detected_techniques': sum(1 for t in coverage_analysis.values() if t['detected'])
        }

    async def get_siem_status(self) -> Dict[str, Any]:
        """
        Check SIEM connectivity and configuration
        """
        siem_type = self.siem_config.get('type', 'test')
        endpoint = self.siem_config.get('api_endpoint')
        
        if not endpoint and siem_type != 'test':
            return {'status': 'not_configured', 'message': 'SIEM endpoint not configured'}
        
        try:
            # Test connection
            if siem_type == 'test':
                return {'status': 'connected', 'mode': 'test', 'message': 'Test mode active'}
            
            adapter = self.siem_adapters.get(siem_type)
            if not adapter:
                return {'status': 'error', 'message': f'Unsupported SIEM type: {siem_type}'}
            
            # Simple connectivity test
            test_result = await self._test_siem_connection()
            
            return {
                'status': 'connected' if test_result else 'error',
                'siem_type': siem_type,
                'endpoint': endpoint,
                'configured': bool(endpoint),
                'test_result': test_result
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'siem_type': siem_type}

    async def simulate_detection(self, technique_ids: List[str], 
                                 timeframe_hours: int = 24) -> Dict[str, Any]:
        """
        Simulate detection for specific techniques
        Useful for testing without running full operations
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=timeframe_hours)
        
        events = []
        for technique in technique_ids:
            technique_events = await self._fetch_events_for_technique(start_time, end_time, technique)
            events.extend(technique_events)
        
        return {
            'simulation_timeframe': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'techniques_tested': technique_ids,
            'events_found': len(events),
            'detected_techniques': list(set(e['technique_id'] for e in events)),
            'detection_rate': len(set(e['technique_id'] for e in events)) / len(technique_ids) * 100
        }

    # Internal helper methods

    async def _extract_techniques(self, operation) -> List[str]:
        """Extract MITRE technique IDs from operation links"""
        techniques = set()
        for link in operation.chain:
            if (hasattr(link, 'ability') and link.ability and 
                hasattr(link.ability, 'technique_id') and link.ability.technique_id):
                techniques.add(link.ability.technique_id)
        
        # Also check for tactics if available
        for link in operation.chain:
            if (hasattr(link, 'ability') and link.ability and 
                hasattr(link.ability, 'tactic') and link.ability.tactic):
                # Convert tactic to relevant techniques if needed
                pass
        
        return list(techniques)

    async def _fetch_siem_events(self, start_time: datetime, 
                                end_time: datetime, 
                                techniques: List[str]) -> List[Dict]:
        """Fetch events from configured SIEM"""
        siem_type = self.siem_config.get('type', 'test')
        
        # Check cache first
        cache_key = f"{siem_type}_{start_time.timestamp()}_{end_time.timestamp()}_{hash(tuple(techniques))}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() - cached['timestamp'] < self.cache_ttl:
                return cached['events']
        
        # Use appropriate adapter
        adapter = self.siem_adapters.get(siem_type, self._query_test_mode)
        events = await adapter(start_time, end_time, techniques)
        
        # Cache results
        self.cache[cache_key] = {
            'timestamp': datetime.now(),
            'events': events
        }
        
        return events

    async def _fetch_events_for_technique(self, start_time: datetime, 
                                         end_time: datetime, 
                                         technique: str) -> List[Dict]:
        """Fetch events for a single technique"""
        return await self._fetch_siem_events(start_time, end_time, [technique])

    async def _analyze_detection_coverage(self, techniques_used: List[str], 
                                         siem_events: List[Dict],
                                         operation) -> Dict[str, Any]:
        """Analyze detection coverage and generate insights"""
        detected_techniques = set(event['technique_id'] for event in siem_events if 'technique_id' in event)
        
        # Calculate detection latency
        detection_latencies = []
        for event in siem_events:
            if 'timestamp' in event and operation.start:
                event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                latency = (event_time - operation.start).total_seconds()
                detection_latencies.append(latency)
        
        # Group events by technique
        events_by_technique = {}
        for event in siem_events:
            tech = event.get('technique_id', 'unknown')
            events_by_technique.setdefault(tech, []).append(event)
        
        return {
            'detected_techniques': list(detected_techniques),
            'undetected_techniques': [t for t in techniques_used if t not in detected_techniques],
            'detection_rate': len(detected_techniques) / len(techniques_used) * 100 if techniques_used else 0,
            'avg_detection_latency': sum(detection_latencies) / len(detection_latencies) if detection_latencies else None,
            'min_detection_latency': min(detection_latencies) if detection_latencies else None,
            'max_detection_latency': max(detection_latencies) if detection_latencies else None,
            'events_by_technique': events_by_technique,
            'total_events': len(siem_events)
        }

    async def _generate_detection_report(self, operation, techniques_used: List[str],
                                        siem_events: List[Dict], 
                                        analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive detection report"""
        return {
            'operation_id': operation.id,
            'operation_name': operation.name,
            'operation_start': operation.start.isoformat() if operation.start else None,
            'operation_finish': operation.finish.isoformat() if operation.finish else None,
            'techniques_used': techniques_used,
            'techniques_detected': analysis['detected_techniques'],
            'undetected_techniques': analysis['undetected_techniques'],
            'detection_rate': round(analysis['detection_rate'], 2),
            'siem_events_count': len(siem_events),
            'detection_latency': {
                'average_seconds': analysis['avg_detection_latency'],
                'min_seconds': analysis['min_detection_latency'],
                'max_seconds': analysis['max_detection_latency']
            },
            'siem_type': self.siem_config.get('type', 'test'),
            'analysis_timestamp': datetime.now().isoformat(),
            'recommendations': await self._generate_recommendations(analysis)
        }

    async def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        detection_rate = analysis['detection_rate']
        if detection_rate < 30:
            recommendations.append("Low detection rate. Consider tuning SIEM rules or adding additional detection mechanisms.")
        elif detection_rate < 70:
            recommendations.append("Moderate detection rate. Review undetected techniques for rule improvements.")
        else:
            recommendations.append("Good detection rate. Focus on reducing detection latency.")
        
        if analysis['undetected_techniques']:
            recommendations.append(f"Undetected techniques: {', '.join(analysis['undetected_techniques'][:3])}...")
        
        if analysis['avg_detection_latency'] and analysis['avg_detection_latency'] > 3600:  # > 1 hour
            recommendations.append("High detection latency. Investigate SIEM processing delays.")
        
        return recommendations

    # SIEM Adapters

    async def _query_arcsight(self, start_time: datetime, end_time: datetime, 
                             techniques: List[str]) -> List[Dict]:
        """Query ArcSight SIEM"""
        endpoint = self.siem_config.get('api_endpoint')
        token = self.siem_config.get('api_token')
        
        if not endpoint or not token:
            self.log.warning("ArcSight endpoint or token not configured")
            return []
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        query = {
            "startTime": start_time.isoformat(),
            "endTime": end_time.isoformat(),
            "techniques": techniques,
            "limit": 1000  # Configurable
        }
        
        try:
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.post(f"{endpoint}/api/search", 
                                      headers=headers, 
                                      json=query) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('events', [])
                    else:
                        self.log.error(f"ArcSight API error: {resp.status}")
        except Exception as e:
            self.log.error(f"ArcSight query failed: {str(e)}")
        
        return []

    async def _query_splunk(self, start_time: datetime, end_time: datetime,
                           techniques: List[str]) -> List[Dict]:
        """Query Splunk SIEM"""
        endpoint = self.siem_config.get('api_endpoint')
        token = self.siem_config.get('api_token')
        
        if not endpoint or not token:
            self.log.warning("Splunk endpoint or token not configured")
            return []
        
        # Build SPL query
        technique_query = " OR ".join([f'technique_id="{t}"' for t in techniques])
        spl = f'search {technique_query} | head 1000'
        
        query = {
            "search": spl,
            "earliest_time": start_time.timestamp(),
            "latest_time": end_time.timestamp()
        }
        
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            async with ClientSession() as session:
                async with session.post(f"{endpoint}/services/search/jobs", 
                                      headers=headers, 
                                      json=query) as resp:
                    if resp.status == 201:
                        data = await resp.json()
                        # Would need to poll for results in real implementation
                        return []
        except Exception as e:
            self.log.error(f"Splunk query failed: {str(e)}")
        
        return []

    async def _query_qradar(self, start_time: datetime, end_time: datetime,
                           techniques: List[str]) -> List[Dict]:
        """Query QRadar SIEM"""
        # Implementation for QRadar
        return []

    async def _query_elastic(self, start_time: datetime, end_time: datetime,
                            techniques: List[str]) -> List[Dict]:
        """Query Elastic SIEM"""
        # Implementation for Elastic
        return []

    async def _query_test_mode(self, start_time: datetime, end_time: datetime,
                              techniques: List[str]) -> List[Dict]:
        """Test mode - returns simulated events for testing"""
        # Generate mock events for testing
        events = []
        for technique in techniques[:5]:  # Limit to 5 techniques for testing
            # Simulate 70% detection rate
            if hash(technique) % 10 < 7:  # 70% chance of detection
                events.append({
                    'technique_id': technique,
                    'timestamp': (start_time + timedelta(minutes=5)).isoformat(),
                    'event_type': 'test_event',
                    'severity': 'medium',
                    'message': f'Test detection for {technique}',
                    'source': 'test_siem'
                })
        
        return events

    async def _test_siem_connection(self) -> bool:
        """Test SIEM connectivity"""
        siem_type = self.siem_config.get('type', 'test')
        
        if siem_type == 'test':
            return True
        
        try:
            endpoint = self.siem_config.get('api_endpoint')
            if not endpoint:
                return False
            
            # Simple HTTP GET to health endpoint
            async with ClientSession() as session:
                async with session.get(f"{endpoint}/health", timeout=5) as resp:
                    return resp.status < 500
        except:
            return False

    def _cache_results(self, operation_id: str, report: Dict[str, Any]):
        """Cache analysis results"""
        self.cache[f"report_{operation_id}"] = {
            'timestamp': datetime.now(),
            'report': report
        }

    async def get_cached_report(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Get cached report if available and fresh"""
        cache_key = f"report_{operation_id}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() - cached['timestamp'] < self.cache_ttl:
                return cached['report']
        return None
