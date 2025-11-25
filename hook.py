from aiohttp import web
from source.validator import DetectionValidator
from source.siem_client import SIEMClient

async def enable(services):
    app_svc = services.get('app_svc')
    
    # components init 
    siem_client = SIEMClient(services)
    validator = DetectionValidator(services)
    validator.siem_client = siem_client
    
    # save in services 
    services['detection_validator'] = validator
    
    # API endpoints 
    app_svc.application.router.add_route(
        'POST', '/plugin/detection-validator/validate/{operation_id}', 
        lambda request: validate_operation(request, validator)
    )
    
    app_svc.application.router.add_route(
        'GET', '/plugin/detection-validator/results/{operation_id}', 
        lambda request: get_results(request, validator)
    )
    
    print("Detection Validator plugin enabled!")

async def validate_operation(request, validator):
    """Waliduje detekcję dla operacji"""
    operation_id = request.match_info['operation_id']
    
    try:
        report = await validator.validate_operation_detection(operation_id)
        
        if report:
            return web.json_response({
                'status': 'success',
                'message': f'Detection validation completed for {operation_id}',
                'data': report
            })
        else:
            return web.json_response({
                'status': 'error', 
                'message': f'Failed to validate operation {operation_id}'
            }, status=400)
            
    except Exception as e:
        return web.json_response({
            'status': 'error',
            'message': f'Validation error: {str(e)}'
        }, status=500)

async def get_results(request, validator):
    operation_id = request.match_info['operation_id']
    
    html = f"""
    <html>
    <head>
        <title>Detection Validation Results - {operation_id}</title>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            .technique {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
            .detected {{ border-color: green; background: #f0fff0; }}
            .not-detected {{ border-color: red; background: #fff0f0; }}
            .stats {{ background: #f5f5f5; padding: 15px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>Detection Validation: {operation_id}</h1>
        <p>Use POST /plugin/detection-validator/validate/{operation_id} to generate report</p>
    </body>
    </html>
    """
    
    return web.Response(text=html, content_type='text/html')

async def disable(services):
    print("Detection Validator plugin disabled")
