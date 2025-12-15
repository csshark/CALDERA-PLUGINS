"""
DetMeter Plugin for Caldera
Minimal working version
"""
import logging
import os
from aiohttp import web

logger = logging.getLogger('detmeter')

# === WAŻNE: Caldera szuka tych zmiennych na poziomie modułu ===
name = 'detmeter'
address = '/plugins/detmeter'
description = 'SIEM Detection Comparison Tool'

async def enable(services):
    """Funkcja którą Caldera automatycznie wywoła"""
    logger.info('[DetMeter] Enabling plugin...')
    
    try:
        # 1. Importujemy nasz serwis
        from plugins.detmeter.detmeter_svc import DetMeterService
        
        # 2. Tworzymy instancję serwisu
        detmeter_svc = DetMeterService(services)
        
        # 3. Zapisujemy serwis do użycia później
        services['detmeter_svc'] = detmeter_svc
        
        # 4. Pobieramy app z services
        app_svc = services.get('app_svc')
        app = app_svc.application
        
        # 5. Rejestrujemy endpointy
        # 5.1 GUI - strona główna
        async def gui_handler(request):
            html_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
            try:
                with open(html_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                return web.Response(text=html, content_type='text/html')
            except:
                return web.Response(text='<h1>DetMeter</h1><p>GUI template missing</p>', content_type='text/html')
        
        # 5.2 API - pobierz operacje z Caldera
        async def get_operations_handler(request):
            data_svc = services.get('data_svc')
            operations = await data_svc.locate('operations')
            
            result = []
            for op in operations:
                if hasattr(op, 'id'):
                    result.append({
                        'id': op.id,
                        'name': getattr(op, 'name', 'Unnamed'),
                        'start': getattr(op, 'start', None),
                        'state': getattr(op, 'state', 'unknown')
                    })
            
            return web.json_response(result)
        
        # 5.3 API - analizuj operację
        async def analyze_handler(request):
            try:
                data = await request.json()
                operation_id = data.get('operation_id')
                
                if not operation_id:
                    return web.json_response({'error': 'operation_id required'}, status=400)
                
                # Użyj naszego serwisu
                result = await detmeter_svc.analyze_operation(operation_id)
                return web.json_response(result)
                
            except Exception as e:
                logger.error(f'Analyze error: {e}')
                return web.json_response({'error': str(e)}, status=500)
        
        # 5.4 API - status SIEM
        async def status_handler(request):
            status = await detmeter_svc.get_siem_status()
            return web.json_response(status)
        
        # 5.5 API - health check
        async def health_handler(request):
            return web.json_response({
                'status': 'ok',
                'plugin': 'detmeter',
                'endpoints': ['/plugin/detmeter', '/plugin/detmeter/analyze', '/plugin/detmeter/status']
            })
        
        # 6. Rejestracja ścieżek
        # WAŻNE: Używamy /plugin/detmeter/... bo tak działa Caldera
        app.router.add_get('/plugin/detmeter', gui_handler)
        app.router.add_get('/plugin/detmeter/gui', gui_handler)
        app.router.add_get('/plugin/detmeter/api/operations', get_operations_handler)
        app.router.add_post('/plugin/detmeter/api/analyze', analyze_handler)
        app.router.add_get('/plugin/detmeter/api/status', status_handler)
        app.router.add_get('/plugin/detmeter/api/health', health_handler)
        
        logger.info('[DetMeter] Plugin enabled successfully!')
        logger.info('[DetMeter] Access at: http://localhost:8443/plugin/detmeter')
        
        return True
        
    except Exception as e:
        logger.error(f'[DetMeter] FAILED to enable: {str(e)}')
        import traceback
        logger.error(traceback.format_exc())
        return False
