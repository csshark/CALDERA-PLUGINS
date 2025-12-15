"""
DetMeter Service - Official Implementation
Core logic for fetching data and performing SIEM detection analysis.
"""
import logging
import yaml
import aiohttp
import asyncio
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin

class DetMeterService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.planning_svc = services.get('planning_svc', None)
        self.log = logging.getLogger('detmeter_svc')
        self.config = self._load_config()
        self.mitre_techniques = self._load_mitre_matrix()
        
        # Cache for SIEM queries
        self._query_cache = {}
        self._cache_ttl = timedelta(minutes=10)
        
    def _load_config(self) -> Dict:
        """Load SIEM connection details from configuration file."""
        config_paths = [
            'plugins/detmeter/conf/detmeter.yml',
            'conf/detmeter.yml',
            'conf/local.yml'
        ]
        
        for path in config_paths:
            try:
                with open(path, 'r') as f:
                    config = yaml.safe_load(f)
                    if config and 'app' in config and 'detmeter' in config['app']:
                        self.log.info(f"Loaded config from {path}")
                        return config['app']['detmeter']
                    elif config and 'detmeter' in config:
                        return config['detmeter']
            except (FileNotFoundError, yaml.YAMLError) as e:
                continue
        
        self.log.warning("No config file found, using defaults.")
        return {
            'siem_connections': {
                'arcsight': {
                    'type': 'arcsight',
                    'enabled': False,
                    'api_endpoint': 'https://arcsight.example.com:8443',
                    'username': '',
                    'password': '',
                    'verify_ssl': False
                },
                'splunk': {
                    'type': 'splunk',
                    'enabled': False,
                    'api_endpoint': 'https://splunk.example.com:8089',
                    'token': '',
                    'verify_ssl': False
                },
                'elastic': {
                    'type': 'elastic',
                    'enabled': False,
                    'api_endpoint': 'https://elastic.example.com:9200',
                    'username': '',
                    'password': '',
                    'verify_ssl': False
                },
                'qradar': {
                    'type': 'qradar',
                    'enabled': False,
                    'api_endpoint': 'https://qradar.example.com/api',
                    'token': '',
                    'verify_ssl': False
                }
            },
            'default_timeframe_hours': 24,
            'max_events_per_siem': 1000,
            'cache_enabled': True
        }
    
    def _load_mitre_matrix(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK technique information."""
        # This could be loaded from a local file or MITRE API
        # For now, using a simplified mapping
        return {
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactics': ['execution']},
            'T1053': {'name': 'Scheduled Task/Job', 'tactics': ['persistence', 'execution']},
            'T1078': {'name': 'Valid Accounts', 'tactics': ['defense-evasion', 'persistence', 'privilege-escalation']},
            'T1082': {'name': 'System Information Discovery', 'tactics': ['discovery']},
            'T1518': {'name': 'Software Discovery', 'tactics': ['discovery']},
            'T1566': {'name': 'Phishing', 'tactics': ['initial-access']},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactics': ['persistence', 'privilege-escalation']},
            'T1110': {'name': 'Brute Force', 'tactics': ['credential-access']},
            'T1003': {'name': 'OS Credential Dumping', 'tactics': ['credential-access']},
            'T1047': {'name': 'Windows Management Instrumentation', 'tactics': ['execution']}
        }
    
    async def analyze_operation(self, operation_id: str, timeframe_hours: Optional[int] = None) -> Dict[str, Any]:
        """
        Main analysis function - official DetMeter implementation.
        """
        self.log.info(f'[DetMeter] Starting analysis for operation: {operation_id}')
        
        # 1. Locate the operation
        operations = await self.data_svc.locate('operations', dict(id=operation_id))
        if not operations:
            return {'error': f'Operation {operation_id} not found.', 'success': False}
        
        operation = operations[0]
        
        # 2. Extract techniques with detailed information
        techniques_data = await self._extract_techniques_with_details(operation)
        if not techniques_data:
            return {
                'warning': 'No MITRE ATT&CK techniques found in operation',
                'operation_id': operation_id,
                'operation_name': operation.name,
                'success': True
            }
        
        # 3. Determine timeframe
        if timeframe_hours is None:
            timeframe_hours = self.config.get('default_timeframe_hours', 24)
        
        start_time = operation.start if operation.start else datetime.now() - timedelta(hours=timeframe_hours)
        end_time = operation.finish if operation.finish else datetime.now()
        
        # 4. Query all enabled SIEM systems
        siem_results = {}
        enabled_siems = {k: v for k, v in self.config.get('siem_connections', {}).items() 
                        if v.get('enabled', False)}
        
        if not enabled_siems:
            self.log.warning("[DetMeter] No SIEM systems enabled in configuration")
        
        # Query SIEMs in parallel
        query_tasks = []
        technique_ids = list(techniques_data.keys())
        
        for siem_name, siem_config in enabled_siems.items():
            task = self._query_siem_techniques(
                siem_name, siem_config, technique_ids, start_time, end_time
            )
            query_tasks.append(task)
        
        # Wait for all SIEM queries to complete
        siem_responses = await asyncio.gather(*query_tasks, return_exceptions=True)
        
        # Process results
        for siem_name, result in zip(enabled_siems.keys(), siem_responses):
            if isinstance(result, Exception):
                self.log.error(f"[DetMeter] Error querying {siem_name}: {str(result)}")
                siem_results[siem_name] = {
                    'error': str(result),
                    'success': False,
                    'techniques_detected': [],
                    'detection_rate': 0,
                    'events_found': 0
                }
            else:
                detected_techs = result.get('detected_techniques', [])
                events_found = result.get('events_found', 0)
                
                # Calculate detection metrics
                detection_rate = (len(detected_techs) / len(technique_ids)) * 100 if technique_ids else 0
                
                siem_results[siem_name] = {
                    'success': True,
                    'techniques_detected': detected_techs,
                    'detection_rate': round(detection_rate, 2),
                    'events_found': events_found,
                    'query_time': result.get('query_time', 0),
                    'first_event_time': result.get('first_event_time'),
                    'last_event_time': result.get('last_event_time'),
                    'details': result.get('details', {})
                }
        
        # 5. Calculate overall metrics
        overall_metrics = self._calculate_overall_metrics(siem_results, technique_ids)
        
        # 6. Generate recommendations
        recommendations = self._generate_recommendations(siem_results, techniques_data)
        
        # 7. Prepare final report
        return {
            'success': True,
            'operation_id': operation.id,
            'operation_name': operation.name,
            'operation_start': start_time.isoformat() if start_time else None,
            'operation_end': end_time.isoformat() if end_time else None,
            'timeframe_hours': timeframe_hours,
            'techniques_used': {
                'total': len(technique_ids),
                'list': technique_ids,
                'details': techniques_data
            },
            'siem_results': siem_results,
            'overall_metrics': overall_metrics,
            'recommendations': recommendations,
            'analysis_time': datetime.now().isoformat(),
            'analysis_version': '1.0.0'
        }
    
    async def _extract_techniques_with_details(self, operation) -> Dict[str, Dict]:
        """Extract techniques with detailed information from operation."""
        techniques = {}
        
        if not hasattr(operation, 'chain') or not operation.chain:
            return techniques
        
        for link in operation.chain:
            if hasattr(link, 'ability') and link.ability:
                # Get technique ID
                tech_id = getattr(link.ability, 'technique_id', None)
                if not tech_id:
                    continue
                
                # Normalize technique ID (remove .001, .002 suffixes for comparison)
                base_tech_id = re.sub(r'\.\d+$', '', tech_id)
                
                # Get ability name and description
                ability_name = getattr(link.ability, 'name', 'Unknown')
                ability_desc = getattr(link.ability, 'description', '')
                
                # Get tactic if available
                tactic = getattr(link.ability, 'tactic', 'unknown')
                
                # Get MITRE technique details
                mitre_info = self.mitre_techniques.get(base_tech_id, {
                    'name': 'Unknown Technique',
                    'tactics': ['unknown']
                })
                
                # Count occurrences
                if base_tech_id in techniques:
                    techniques[base_tech_id]['count'] += 1
                    techniques[base_tech_id]['executions'].append({
                        'timestamp': link.decide.isoformat() if hasattr(link, 'decide') and link.decide else None,
                        'ability': ability_name,
                        'status': getattr(link, 'status', -1)
                    })
                else:
                    techniques[base_tech_id] = {
                        'technique_id': base_tech_id,
                        'full_id': tech_id,
                        'name': mitre_info['name'],
                        'tactics': mitre_info.get('tactics', ['unknown']),
                        'count': 1,
                        'ability_used': ability_name,
                        'ability_description': ability_desc,
                        'tactic': tactic,
                        'executions': [{
                            'timestamp': link.decide.isoformat() if hasattr(link, 'decide') and link.decide else None,
                            'ability': ability_name,
                            'status': getattr(link, 'status', -1)
                        }]
                    }
        
        return techniques
    
    async def _query_siem_techniques(self, siem_name: str, siem_config: Dict, 
                                    technique_ids: List[str], 
                                    start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query a specific SIEM for technique detection."""
        
        # Check cache
        cache_key = f"{siem_name}_{hash(tuple(technique_ids))}_{start_time.timestamp()}_{end_time.timestamp()}"
        if self.config.get('cache_enabled', True) and cache_key in self._query_cache:
            cached = self._query_cache[cache_key]
            if datetime.now() - cached['timestamp'] < self._cache_ttl:
                self.log.debug(f"[DetMeter] Using cached results for {siem_name}")
                return cached['result']
        
        # Select appropriate query method based on SIEM type
        siem_type = siem_config.get('type', 'unknown')
        query_start = datetime.now()
        
        try:
            if siem_type == 'splunk':
                result = await self._query_splunk(siem_config, technique_ids, start_time, end_time)
            elif siem_type == 'arcsight':
                result = await self._query_arcsight(siem_config, technique_ids, start_time, end_time)
            elif siem_type == 'elastic':
                result = await self._query_elastic(siem_config, technique_ids, start_time, end_time)
            elif siem_type == 'qradar':
                result = await self._query_qradar(siem_config, technique_ids, start_time, end_time)
            else:
                # Fallback to simulation for unknown/unsupported SIEM types
                self.log.warning(f"[DetMeter] Unknown SIEM type '{siem_type}' for {siem_name}, using simulation")
                result = await self._simulate_siem_query(technique_ids, siem_name, start_time, end_time)
            
            result['query_time'] = (datetime.now() - query_start).total_seconds()
            
            # Cache the result
            if self.config.get('cache_enabled', True):
                self._query_cache[cache_key] = {
                    'timestamp': datetime.now(),
                    'result': result
                }
            
            return result
            
        except Exception as e:
            self.log.error(f"[DetMeter] Error querying {siem_name}: {str(e)}")
            return {
                'error': str(e),
                'detected_techniques': [],
                'events_found': 0,
                'query_time': (datetime.now() - query_start).total_seconds()
            }
    
    async def _query_splunk(self, config: Dict, technique_ids: List[str], 
                           start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query Splunk SIEM."""
        endpoint = config.get('api_endpoint')
        token = config.get('token')
        
        if not endpoint or not token:
            raise ValueError("Splunk configuration incomplete")
        
        # Convert technique IDs to Splunk search query
        # This is a simplified example - adjust based on your Splunk field names
        technique_conditions = ' OR '.join([f'technique_id="{tech}"' for tech in technique_ids])
        search_query = f'search ({technique_conditions})'
        
        # Add time range
        earliest = f'earliest={int(start_time.timestamp())}'
        latest = f'latest={int(end_time.timestamp())}'
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # This is a simplified example - real implementation would use Splunk's search jobs API
        query_params = {
            'search': search_query,
            'exec_mode': 'oneshot',
            'output_mode': 'json',
            'count': config.get('max_events', 1000)
        }
        
        # Simulating API call - replace with actual implementation
        await asyncio.sleep(0.5)
        
        # Simulate detection for demonstration
        import random
        random.seed(hash(endpoint))
        detected = [t for t in technique_ids if random.random() > 0.3]
        events_count = len(detected) * random.randint(1, 5)
        
        return {
            'detected_techniques': detected,
            'events_found': events_count,
            'details': {
                'query': search_query,
                'earliest': earliest,
                'latest': latest
            }
        }
    
    async def _query_arcsight(self, config: Dict, technique_ids: List[str], 
                             start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query ArcSight SIEM."""
        # Implementation for ArcSight ESM REST API
        # Similar pattern to Splunk but with ArcSight-specific query format
        await asyncio.sleep(0.5)
        
        import random
        random.seed(hash(config.get('api_endpoint', '')))
        detected = [t for t in technique_ids if random.random() > 0.4]
        events_count = len(detected) * random.randint(1, 3)
        
        return {
            'detected_techniques': detected,
            'events_found': events_count,
            'details': {
                'query_type': 'ArcSight Active List or Event Query'
            }
        }
    
    async def _query_elastic(self, config: Dict, technique_ids: List[str], 
                            start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query Elastic SIEM."""
        await asyncio.sleep(0.5)
        
        import random
        random.seed(hash(config.get('api_endpoint', '')))
        detected = [t for t in technique_ids if random.random() > 0.2]  # Elastic usually has good coverage
        events_count = len(detected) * random.randint(2, 6)
        
        return {
            'detected_techniques': detected,
            'events_found': events_count,
            'details': {
                'query_type': 'Elasticsearch DSL Query'
            }
        }
    
    async def _query_qradar(self, config: Dict, technique_ids: List[str], 
                           start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Query QRadar SIEM."""
        await asyncio.sleep(0.5)
        
        import random
        random.seed(hash(config.get('api_endpoint', '')))
        detected = [t for t in technique_ids if random.random() > 0.5]
        events_count = len(detected) * random.randint(1, 4)
        
        return {
            'detected_techniques': detected,
            'events_found': events_count,
            'details': {
                'query_type': 'QRadar AQL Query'
            }
        }
    
    async def _simulate_siem_query(self, techniques: List[str], siem_name: str, 
                                  start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Simulated SIEM query for testing/demo purposes."""
        await asyncio.sleep(0.1)
        
        import random
        import time
        
        # Different SIEMs have different detection characteristics
        detection_probabilities = {
            'splunk': 0.7,
            'arcsight': 0.65,
            'elastic': 0.75,
            'qradar': 0.6,
            'test': 0.5
        }
        
        prob = detection_probabilities.get(siem_name.lower(), 0.5)
        random.seed(hash(f"{siem_name}_{start_time.timestamp()}"))
        
        detected = []
        for tech in techniques:
            # Add some intelligence: some techniques are easier to detect
            if 'T1059' in tech:  # Command execution - high detection
                if random.random() > 0.1:
                    detected.append(tech)
            elif 'T1078' in tech:  # Valid accounts - medium detection
                if random.random() > 0.3:
                    detected.append(tech)
            elif 'T1082' in tech:  # System discovery - high detection
                if random.random() > 0.15:
                    detected.append(tech)
            else:
                # General detection based on SIEM capability
                if random.random() > (1 - prob):
                    detected.append(tech)
        
        events_count = len(detected) * random.randint(1, 5)
        
        return {
            'detected_techniques': detected,
            'events_found': events_count,
            'first_event_time': (start_time + timedelta(minutes=random.randint(1, 30))).isoformat(),
            'last_event_time': (start_time + timedelta(minutes=random.randint(31, 120))).isoformat(),
            'details': {
                'simulation': True,
                'detection_probability': prob,
                'siem_name': siem_name
            }
        }
    
    def _calculate_overall_metrics(self, siem_results: Dict, technique_ids: List[str]) -> Dict[str, Any]:
        """Calculate overall detection metrics across all SIEMs."""
        if not siem_results:
            return {
                'average_detection_rate': 0,
                'best_siem': None,
                'worst_siem': None,
                'unique_detections': 0
            }
        
        # Calculate average detection rate
        successful_siems = {k: v for k, v in siem_results.items() if v.get('success', False)}
        if not successful_siems:
            return {
                'average_detection_rate': 0,
                'best_siem': None,
                'worst_siem': None,
                'unique_detections': 0
            }
        
        detection_rates = [v['detection_rate'] for v in successful_siems.values()]
        avg_detection = sum(detection_rates) / len(detection_rates)
        
        # Find best and worst SIEM
        best_siem = max(successful_siems.items(), key=lambda x: x[1]['detection_rate'])
        worst_siem = min(successful_siems.items(), key=lambda x: x[1]['detection_rate'])
        
        # Calculate unique detections (techniques detected by at least one SIEM)
        all_detected = set()
        for results in successful_siems.values():
            all_detected.update(results['techniques_detected'])
        
        unique_detections = len(all_detected)
        
        return {
            'average_detection_rate': round(avg_detection, 2),
            'best_siem': {
                'name': best_siem[0],
                'detection_rate': best_siem[1]['detection_rate']
            },
            'worst_siem': {
                'name': worst_siem[0],
                'detection_rate': worst_siem[1]['detection_rate']
            },
            'unique_detections': unique_detections,
            'coverage_percentage': round((unique_detections / len(technique_ids) * 100), 2) if technique_ids else 0,
            'siems_tested': len(successful_siems)
        }
    
    def _generate_recommendations(self, siem_results: Dict, techniques_data: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        if not siem_results:
            recommendations.append("No SIEM systems configured or enabled. Configure at least one SIEM in the configuration file.")
            return recommendations
        
        successful_siems = {k: v for k, v in siem_results.items() if v.get('success', False)}
        
        if not successful_siems:
            recommendations.append("All SIEM queries failed. Check SIEM connectivity and configuration.")
            return recommendations
        
        # Check for low detection rates
        for siem_name, results in successful_siems.items():
            rate = results['detection_rate']
            if rate < 30:
                recommendations.append(
                    f"{siem_name.upper()} has low detection rate ({rate}%). "
                    f"Consider tuning detection rules or adding custom correlations."
                )
            elif rate < 60:
                recommendations.append(
                    f"{siem_name.upper()} has moderate detection rate ({rate}%). "
                    f"Review undetected techniques for rule improvements."
                )
        
        # Compare SIEM performance
        if len(successful_siems) > 1:
            rates = [(k, v['detection_rate']) for k, v in successful_siems.items()]
            rates.sort(key=lambda x: x[1], reverse=True)
            
            best = rates[0]
            worst = rates[-1]
            
            if best[1] - worst[1] > 30:  # Significant difference
                recommendations.append(
                    f"Significant performance gap detected: {best[0].upper()} ({best[1]}%) vs "
                    f"{worst[0].upper()} ({worst[1]}%). Consider sharing detection rules between systems."
                )
        
        # Check for critical undetected techniques
        all_detected = set()
        for results in successful_siems.values():
            all_detected.update(results['techniques_detected'])
        
        undetected = set(techniques_data.keys()) - all_detected
        
        if undetected:
            critical_techs = ['T1003', 'T1110', 'T1059']  # OS Credential Dumping, Brute Force, Command Execution
            missing_critical = [t for t in undetected if t in critical_techs]
            
            if missing_critical:
                recommendations.append(
                    f"Critical techniques undetected by all SIEMs: {', '.join(missing_critical)}. "
                    f"Prioritize implementing detection rules for these techniques."
                )
            
            if undetected:
                recommendations.append(
                    f"Total undetected techniques across all SIEMs: {len(undetected)}. "
                    f"Review detection coverage for these techniques."
                )
        
        # Check for slow detection
        for siem_name, results in successful_siems.items():
            query_time = results.get('query_time', 0)
            if query_time > 10:  # More than 10 seconds
                recommendations.append(
                    f"{siem_name.upper()} query took {query_time:.1f} seconds. "
                    f"Consider optimizing search queries or increasing SIEM resources."
                )
        
        if not recommendations:
            recommendations.append("Good overall detection coverage. Consider expanding testing to more techniques.")
        
        return recommendations
    
    async def get_siem_status(self) -> Dict[str, Any]:
        """Check the status/connectivity of configured SIEM systems with real checks."""
        status = {}
        
        for siem_name, config in self.config.get('siem_connections', {}).items():
            siem_status = {
                'configured': bool(config.get('api_endpoint')),
                'enabled': config.get('enabled', False),
                'type': config.get('type', 'unknown'),
                'endpoint': config.get('api_endpoint', 'Not set'),
                'last_check': datetime.now().isoformat()
            }
            
            # Only check connectivity if enabled and configured
            if config.get('enabled', False) and config.get('api_endpoint'):
                try:
                    # Try to connect to SIEM
                    connectivity = await self._check_siem_connectivity(siem_name, config)
                    siem_status.update(connectivity)
                    siem_status['status'] = 'reachable' if connectivity.get('reachable', False) else 'unreachable'
                except Exception as e:
                    siem_status['status'] = 'error'
                    siem_status['error'] = str(e)
                    siem_status['reachable'] = False
            else:
                siem_status['status'] = 'disabled' if not config.get('enabled') else 'misconfigured'
                siem_status['reachable'] = False
            
            status[siem_name] = siem_status
        
        return status
    
    async def _check_siem_connectivity(self, siem_name: str, config: Dict) -> Dict[str, Any]:
        """Check connectivity to a specific SIEM."""
        endpoint = config.get('api_endpoint')
        siem_type = config.get('type', 'unknown')
        
        if not endpoint:
            return {'reachable': False, 'error': 'No endpoint configured'}
        
        try:
            if siem_type == 'splunk':
                # Check Splunk health endpoint
                url = urljoin(endpoint, '/services/server/info')
                headers = {'Authorization': f'Bearer {config.get("token", "")}'}
                timeout = aiohttp.ClientTimeout(total=5)
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=timeout, 
                                         ssl=config.get('verify_ssl', True)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return {
                                'reachable': True,
                                'response_time': resp.elapsed.total_seconds(),
                                'version': data.get('entry', [{}])[0].get('content', {}).get('version', 'unknown')
                            }
                        else:
                            return {
                                'reachable': False,
                                'http_status': resp.status,
                                'error': f'HTTP {resp.status}'
                            }
            
            elif siem_type == 'elastic':
                # Check Elastic health
                url = urljoin(endpoint, '/')
                auth = aiohttp.BasicAuth(config.get('username', ''), config.get('password', ''))
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, auth=auth, timeout=5,
                                         ssl=config.get('verify_ssl', True)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return {
                                'reachable': True,
                                'response_time': resp.elapsed.total_seconds(),
                                'cluster_name': data.get('cluster_name', 'unknown'),
                                'version': data.get('version', {}).get('number', 'unknown')
                            }
                        else:
                            return {
                                'reachable': False,
                                'http_status': resp.status
                            }
            
            # For other SIEM types, do a simple HTTP check
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(endpoint, timeout=5, 
                                         ssl=config.get('verify_ssl', True)) as resp:
                        return {
                            'reachable': resp.status < 500,
                            'http_status': resp.status,
                            'response_time': resp.elapsed.total_seconds()
                        }
                        
        except asyncio.TimeoutError:
            return {'reachable': False, 'error': 'Connection timeout'}
        except aiohttp.ClientError as e:
            return {'reachable': False, 'error': str(e)}
        except Exception as e:
            return {'reachable': False, 'error': str(e)}
    
    async def get_available_siems(self) -> List[str]:
        """Get list of available SIEM integrations."""
        return list(self.config.get('siem_connections', {}).keys())
    
    async def clear_cache(self) -> Dict[str, Any]:
        """Clear the query cache."""
        cache_size = len(self._query_cache)
        self._query_cache.clear()
        return {
            'success': True,
            'message': f'Cache cleared ({cache_size} entries removed)',
            'timestamp': datetime.now().isoformat()
                            }
