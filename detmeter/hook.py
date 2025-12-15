"""
DetMeter Plugin for Caldera - FIXED VERSION
Doesn't hijack all /plugin/ routes
"""
import logging
import os
from aiohttp import web

logger = logging.getLogger('detmeter')

# === METADATA PLUGINU ===
name = 'detmeter'
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
        
        # 5. Rejestrujemy endpointy - UŻYWAMY SPECJALNEJ ŚCIEŻKI
        # 5.1 GUI - strona główna
        async def gui_handler(request):
            html_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
            try:
                with open(html_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                return web.Response(text=html, content_type='text/html')
            except:
                return web.Response(
                    text='<h1>DetMeter</h1><p>GUI template missing</p><p><a href="/">Back to Caldera</a></p>',
                    content_type='text/html'
                )
        
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
                'endpoints': {
                    'gui': '/detmeter/gui',
                    'api': {
                        'operations': '/detmeter/api/operations',
                        'analyze': '/detmeter/api/analyze',
                        'status': '/detmeter/api/status'
                    }
                }
            })
        
        # === WAŻNE: UŻYWAMY /detmeter/* a NIE /plugin/detmeter/* ===
        # To zapobiega przejęciu wszystkich /plugin/* routes
        
        # GUI routes
        app.router.add_get('/detmeter', gui_handler)
        app.router.add_get('/detmeter/gui', gui_handler)
        
        # API routes
        app.router.add_get('/detmeter/api/operations', get_operations_handler)
        app.router.add_post('/detmeter/api/analyze', analyze_handler)
        app.router.add_get('/detmeter/api/status', status_handler)
        app.router.add_get('/detmeter/api/health', health_handler)
        
        # Link do pluginu w głównym interfejsie Caldera
        async def detmeter_redirect(request):
            """Redirect do głównego GUI pluginu"""
            raise web.HTTPFound('/detmeter')
        
        # Rejestrujemy pod /plugin/detmeter ale tylko jako redirect
        app.router.add_get('/plugin/detmeter', detmeter_redirect)
        
        logger.info('[DetMeter] Plugin enabled successfully!')
        logger.info('[DetMeter] Access at: http://localhost:8443/detmeter')
        logger.info('[DetMeter] Caldera GUI still at: http://localhost:8443/')
        
        return True
        
    except Exception as e:
        logger.error(f'[DetMeter] FAILED to enable: {str(e)}')
        import traceback
        logger.error(traceback.format_exc())
        return False
