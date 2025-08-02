"""
Prashant918 Advanced Antivirus - Web API
RESTful API for remote management and monitoring
"""

import os
import sys
import json
import time
from typing import Dict, Any, Optional
from pathlib import Path

# Flask imports with error handling
try:
    from flask import Flask, request, jsonify, send_from_directory
    from flask_cors import CORS
    from werkzeug.security import check_password_hash, generate_password_hash
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    Flask = None
    CORS = None

# Core imports with error handling
try:
    from ..logger import SecureLogger
except ImportError:
    import logging
    SecureLogger = logging.getLogger

try:
    from ..config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

try:
    from ..exceptions import AntivirusError
except ImportError:
    class AntivirusError(Exception):
        pass

class APIManager:
    """API management class"""
    
    def __init__(self):
        self.logger = SecureLogger("API")
        self.threat_engine = None
        self.quarantine_manager = None
        self.service_manager = None
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize API components"""
        try:
            from ..antivirus.engine import AdvancedThreatDetectionEngine
            self.threat_engine = AdvancedThreatDetectionEngine()
        except ImportError:
            self.logger.warning("Threat engine not available for API")
        
        try:
            from ..core.quarantine import QuarantineManager
            self.quarantine_manager = QuarantineManager()
        except ImportError:
            self.logger.warning("Quarantine manager not available for API")
        
        try:
            from ..service.service_manager import create_service_manager
            self.service_manager = create_service_manager()
        except ImportError:
            self.logger.warning("Service manager not available for API")

def create_app(config=None):
    """Create Flask application"""
    if not HAS_FLASK:
        raise ImportError("Flask dependencies not available. Install with: pip install Flask Flask-CORS")
    
    app = Flask(__name__)
    
    # Configure CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:*", "http://127.0.0.1:*"],
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Configuration
    app.config.update({
        'SECRET_KEY': secure_config.get('api.secret_key', 'dev-secret-key'),
        'DEBUG': secure_config.get('api.debug', False),
        'HOST': secure_config.get('api.host', '127.0.0.1'),
        'PORT': secure_config.get('api.port', 5000)
    })
    
    # Initialize API manager
    api_manager = APIManager()
    
    # API Routes
    @app.route('/api/v1/status', methods=['GET'])
    def get_status():
        """Get system status"""
        try:
            status = {
                'status': 'running',
                'version': '1.0.2',
                'timestamp': time.time(),
                'components': {
                    'threat_engine': api_manager.threat_engine is not None,
                    'quarantine_manager': api_manager.quarantine_manager is not None,
                    'service_manager': api_manager.service_manager is not None
                }
            }
            return jsonify(status)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/scan', methods=['POST'])
    def scan_file():
        """Scan a file"""
        try:
            if not api_manager.threat_engine:
                return jsonify({'error': 'Threat engine not available'}), 503
            
            data = request.get_json()
            if not data or 'file_path' not in data:
                return jsonify({'error': 'file_path required'}), 400
            
            file_path = data['file_path']
            if not os.path.exists(file_path):
                return jsonify({'error': 'File not found'}), 404
            
            result = api_manager.threat_engine.scan_file(file_path)
            
            return jsonify({
                'file_path': result.file_path,
                'threat_level': result.threat_level.value if hasattr(result.threat_level, 'value') else str(result.threat_level),
                'confidence': result.confidence,
                'detection_method': result.detection_method,
                'scan_time': result.scan_time
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/quarantine', methods=['GET'])
    def list_quarantine():
        """List quarantined items"""
        try:
            if not api_manager.quarantine_manager:
                return jsonify({'error': 'Quarantine manager not available'}), 503
            
            items = api_manager.quarantine_manager.list_quarantined_items()
            return jsonify({'items': items})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/service/status', methods=['GET'])
    def service_status():
        """Get service status"""
        try:
            if not api_manager.service_manager:
                return jsonify({'error': 'Service manager not available'}), 503
            
            status = api_manager.service_manager.get_service_status()
            return jsonify(status)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/info', methods=['GET'])
    def system_info():
        """Get system information"""
        try:
            import platform
            import psutil
            
            info = {
                'system': {
                    'platform': platform.system(),
                    'release': platform.release(),
                    'version': platform.version(),
                    'machine': platform.machine(),
                    'processor': platform.processor(),
                    'python_version': platform.python_version()
                },
                'resources': {
                    'cpu_count': psutil.cpu_count(),
                    'memory_total': psutil.virtual_memory().total,
                    'memory_available': psutil.virtual_memory().available,
                    'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
                },
                'antivirus': {
                    'version': '1.0.2',
                    'components': {
                        'threat_engine': api_manager.threat_engine is not None,
                        'quarantine_manager': api_manager.quarantine_manager is not None,
                        'service_manager': api_manager.service_manager is not None
                    }
                }
            }
            
            return jsonify(info)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Serve static files
    @app.route('/')
    def index():
        """Serve main page"""
        try:
            web_dir = Path(__file__).parent.parent.parent.parent / "web"
            if web_dir.exists():
                return send_from_directory(str(web_dir), 'index.html')
            else:
                return jsonify({
                    'message': 'Prashant918 Advanced Antivirus API',
                    'version': '1.0.2',
                    'endpoints': [
                        '/api/v1/status',
                        '/api/v1/scan',
                        '/api/v1/quarantine',
                        '/api/v1/service/status',
                        '/api/v1/info'
                    ]
                })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/<path:filename>')
    def static_files(filename):
        """Serve static files"""
        try:
            web_dir = Path(__file__).parent.parent.parent.parent / "web"
            if web_dir.exists():
                return send_from_directory(str(web_dir), filename)
            else:
                return jsonify({'error': 'File not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app

def main():
    """Run the API server"""
    try:
        app = create_app()
        host = app.config.get('HOST', '127.0.0.1')
        port = app.config.get('PORT', 5000)
        debug = app.config.get('DEBUG', False)
        
        print(f"Starting Prashant918 Advanced Antivirus API server...")
        print(f"Server running at: http://{host}:{port}")
        print("Press Ctrl+C to stop")
        
        app.run(host=host, port=port, debug=debug)
        
    except ImportError as e:
        print(f"Error: {e}")
        print("Install Flask dependencies: pip install Flask Flask-CORS")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to start API server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()