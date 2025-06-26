"""
Prashant918 Advanced Antivirus - Web API Interface

RESTful API for remote management and integration with other systems.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from functools import wraps
import os
import tempfile
from typing import Dict, Any, Optional

from ..core.engine import AdvancedThreatDetectionEngine
from ..core.quarantine import QuarantineManager
from ..core.signatures import AdvancedSignatureManager
from ..logger import SecureLogger
from ..config import secure_config
from ..exceptions import AntivirusError, handle_exception

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secure_config.get('api.secret_key', 'change-this-in-production')
app.config['MAX_CONTENT_LENGTH'] = secure_config.get('api.max_file_size', 100 * 1024 * 1024)  # 100MB

# Enable CORS
CORS(app)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

# Initialize components
logger = SecureLogger("WebAPI")
threat_engine = AdvancedThreatDetectionEngine()
quarantine_manager = QuarantineManager()
signature_manager = AdvancedSignatureManager()


def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            payload = jwt.decode(
                token, 
                app.config['SECRET_KEY'], 
                algorithms=['HS256']
            )
            
            request.user = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        status = threat_engine.get_engine_status()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'engine_status': status
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Authentication endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Simple authentication (implement proper auth in production)
        if username == 'admin' and password == secure_config.get('api.admin_password', 'admin'):
            token = jwt.encode({
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'expires_in': 86400  # 24 hours
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/scan/file', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def scan_file():
    """Scan uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Scan the file
            scan_result = threat_engine.scan_file(temp_path)
            
            # Add original filename to result
            scan_result['original_filename'] = file.filename
            
            return jsonify({
                'success': True,
                'result': scan_result
            })
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        logger.error(f"File scan API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/scan/path', methods=['POST'])
@require_auth
def scan_path():
    """Scan file by path"""
    try:
        data = request.get_json()
        file_path = data.get('path')
        
        if not file_path:
            return jsonify({'error': 'No path provided'}), 400
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Scan the file
        scan_result = threat_engine.scan_file(file_path)
        
        return jsonify({
            'success': True,
            'result': scan_result
        })
        
    except Exception as e:
        logger.error(f"Path scan API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/quarantine', methods=['GET'])
@require_auth
def list_quarantine():
    """List quarantined files"""
    try:
        status = request.args.get('status', 'QUARANTINED')
        items = quarantine_manager.list_quarantined_items(status)
        
        return jsonify({
            'success': True,
            'items': items,
            'count': len(items)
        })
        
    except Exception as e:
        logger.error(f"Quarantine list API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/quarantine/<quarantine_id>/restore', methods=['POST'])
@require_auth
def restore_quarantine(quarantine_id):
    """Restore file from quarantine"""
    try:
        data = request.get_json() or {}
        restore_path = data.get('restore_path')
        
        result = quarantine_manager.restore_file(quarantine_id, restore_path)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'File restored successfully',
                'restore_path': result['restore_path']
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400
            
    except Exception as e:
        logger.error(f"Quarantine restore API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/quarantine/<quarantine_id>', methods=['DELETE'])
@require_auth
def delete_quarantine(quarantine_id):
    """Delete quarantined file"""
    try:
        result = quarantine_manager.delete_quarantined_file(quarantine_id)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'File deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400
            
    except Exception as e:
        logger.error(f"Quarantine delete API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/signatures/update', methods=['POST'])
@require_auth
def update_signatures():
    """Update threat signatures"""
    try:
        success = signature_manager.update_from_cloud()
        
        if success:
            stats = signature_manager.get_signature_stats()
            return jsonify({
                'success': True,
                'message': 'Signatures updated successfully',
                'stats': stats
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Signature update failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Signature update API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/signatures/stats', methods=['GET'])
@require_auth
def signature_stats():
    """Get signature statistics"""
    try:
        stats = signature_manager.get_signature_stats()
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Signature stats API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/system/status', methods=['GET'])
@require_auth
def system_status():
    """Get system status"""
    try:
        from ..utils import get_system_info
        
        system_info = get_system_info()
        engine_status = threat_engine.get_engine_status()
        quarantine_stats = quarantine_manager.get_quarantine_stats()
        
        return jsonify({
            'success': True,
            'system_info': system_info,
            'engine_status': engine_status,
            'quarantine_stats': quarantine_stats
        })
        
    except Exception as e:
        logger.error(f"System status API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/threats/statistics', methods=['GET'])
@require_auth
def threat_statistics():
    """Get threat detection statistics"""
    try:
        stats = signature_manager.get_threat_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Threat statistics API error: {e}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def file_too_large(e):
    """Handle file too large error"""
    return jsonify({
        'error': 'File too large',
        'max_size': app.config['MAX_CONTENT_LENGTH']
    }), 413


@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle rate limit exceeded"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': e.retry_after
    }), 429


def run_api_server(host='127.0.0.1', port=5000, debug=False):
    """Run the API server"""
    logger.info(f"Starting API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_api_server()