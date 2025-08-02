"""
Prashant918 Advanced Antivirus - Web GUI Application
Enhanced web interface with real-time monitoring and comprehensive dashboard
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    from flask import Flask, render_template, request, jsonify, send_from_directory, session
    from flask_cors import CORS
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None
    SocketIO = None

# Import antivirus components with fallbacks
try:
    from ..logger import SecureLogger
    from ..config import SecureConfig
    from ..antivirus.engine import AdvancedThreatDetectionEngine
    from ..core.quarantine import QuarantineManager
    from ..core.realtime_monitor import RealtimeMonitor
    from ..antivirus.signatures import AdvancedSignatureManager
    from ..service.service_manager import ServiceManager
    from ..exceptions import AntivirusError
except ImportError:
    # Fallback imports for development
    import logging
    SecureLogger = logging.getLogger
    SecureConfig = dict
    AdvancedThreatDetectionEngine = None
    QuarantineManager = None
    RealtimeMonitor = None
    AdvancedSignatureManager = None
    ServiceManager = None
    AntivirusError = Exception

class AntivirusWebApp:
    """Main web application class for Prashant918 Advanced Antivirus"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = SecureLogger("WebApp")
        
        # Initialize Flask app
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required for web GUI functionality")
            
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.secret_key = self.config.get('secret_key', 'prashant918-antivirus-secret')
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Enable CORS
        CORS(self.app)
        
        # Initialize antivirus components
        self.threat_engine = None
        self.quarantine_manager = None
        self.realtime_monitor = None
        self.signature_manager = None
        self.service_manager = None
        
        self._initialize_components()
        self._setup_routes()
        self._setup_socketio_events()
        
        # Application state
        self.active_scans = {}
        self.system_stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'quarantined_files': 0,
            'last_scan': None,
            'uptime': datetime.now()
        }
        
        # Start background tasks
        self._start_background_tasks()
    
    def _initialize_components(self):
        """Initialize antivirus components with error handling"""
        try:
            if AdvancedThreatDetectionEngine:
                self.threat_engine = AdvancedThreatDetectionEngine()
                self.logger.info("Threat engine initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize threat engine: {e}")
        
        try:
            if QuarantineManager:
                self.quarantine_manager = QuarantineManager()
                self.logger.info("Quarantine manager initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize quarantine manager: {e}")
        
        try:
            if AdvancedSignatureManager:
                self.signature_manager = AdvancedSignatureManager()
                self.logger.info("Signature manager initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize signature manager: {e}")
        
        try:
            if RealtimeMonitor:
                self.realtime_monitor = RealtimeMonitor(
                    threat_engine=self.threat_engine,
                    quarantine_manager=self.quarantine_manager
                )
                # Register threat callback for real-time updates
                self.realtime_monitor.register_threat_callback(self._on_threat_detected)
                self.logger.info("Real-time monitor initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize real-time monitor: {e}")
        
        try:
            if ServiceManager:
                self.service_manager = ServiceManager()
                self.logger.info("Service manager initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize service manager: {e}")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard"""
            return render_template('dashboard.html', 
                                 system_stats=self.system_stats,
                                 components_status=self._get_components_status())
        
        @self.app.route('/scan')
        def scan_page():
            """Scanning interface"""
            return render_template('scan.html')
        
        @self.app.route('/quarantine')
        def quarantine_page():
            """Quarantine management"""
            return render_template('quarantine.html')
        
        @self.app.route('/settings')
        def settings_page():
            """Settings and configuration"""
            return render_template('settings.html')
        
        @self.app.route('/logs')
        def logs_page():
            """System logs viewer"""
            return render_template('logs.html')
        
        # API Routes
        @self.app.route('/api/system/status')
        def api_system_status():
            """Get system status"""
            return jsonify({
                'status': 'running',
                'uptime': str(datetime.now() - self.system_stats['uptime']),
                'components': self._get_components_status(),
                'stats': self.system_stats,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/scan/file', methods=['POST'])
        def api_scan_file():
            """Scan a single file"""
            if not self.threat_engine:
                return jsonify({'error': 'Threat engine not available'}), 503
            
            data = request.get_json()
            file_path = data.get('file_path')
            
            if not file_path or not os.path.exists(file_path):
                return jsonify({'error': 'Invalid file path'}), 400
            
            try:
                # Start scan in background thread
                scan_id = f"scan_{int(time.time())}"
                self.active_scans[scan_id] = {'status': 'running', 'progress': 0}
                
                threading.Thread(
                    target=self._perform_file_scan,
                    args=(scan_id, file_path)
                ).start()
                
                return jsonify({'scan_id': scan_id, 'status': 'started'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/directory', methods=['POST'])
        def api_scan_directory():
            """Scan a directory"""
            if not self.threat_engine:
                return jsonify({'error': 'Threat engine not available'}), 503
            
            data = request.get_json()
            directory_path = data.get('directory_path')
            recursive = data.get('recursive', True)
            
            if not directory_path or not os.path.exists(directory_path):
                return jsonify({'error': 'Invalid directory path'}), 400
            
            try:
                scan_id = f"scan_{int(time.time())}"
                self.active_scans[scan_id] = {'status': 'running', 'progress': 0}
                
                threading.Thread(
                    target=self._perform_directory_scan,
                    args=(scan_id, directory_path, recursive)
                ).start()
                
                return jsonify({'scan_id': scan_id, 'status': 'started'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/status/<scan_id>')
        def api_scan_status(scan_id):
            """Get scan status"""
            if scan_id not in self.active_scans:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify(self.active_scans[scan_id])
        
        @self.app.route('/api/quarantine/list')
        def api_quarantine_list():
            """List quarantined files"""
            if not self.quarantine_manager:
                return jsonify({'error': 'Quarantine manager not available'}), 503
            
            try:
                items = self.quarantine_manager.list_quarantined_files()
                return jsonify({'items': items})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/quarantine/restore/<item_id>', methods=['POST'])
        def api_quarantine_restore(item_id):
            """Restore quarantined file"""
            if not self.quarantine_manager:
                return jsonify({'error': 'Quarantine manager not available'}), 503
            
            try:
                success = self.quarantine_manager.restore_file(item_id)
                return jsonify({'success': success})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/monitor/start', methods=['POST'])
        def api_monitor_start():
            """Start real-time monitoring"""
            if not self.realtime_monitor:
                return jsonify({'error': 'Real-time monitor not available'}), 503
            
            try:
                data = request.get_json() or {}
                paths = data.get('paths', [])
                
                if paths:
                    for path in paths:
                        self.realtime_monitor.add_monitored_path(path)
                
                self.realtime_monitor.start_monitoring()
                return jsonify({'status': 'started'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/monitor/stop', methods=['POST'])
        def api_monitor_stop():
            """Stop real-time monitoring"""
            if not self.realtime_monitor:
                return jsonify({'error': 'Real-time monitor not available'}), 503
            
            try:
                self.realtime_monitor.stop_monitoring()
                return jsonify({'status': 'stopped'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/monitor/status')
        def api_monitor_status():
            """Get monitoring status"""
            if not self.realtime_monitor:
                return jsonify({'error': 'Real-time monitor not available'}), 503
            
            try:
                status = self.realtime_monitor.get_status()
                return jsonify(status)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            self.logger.info("Client connected to WebSocket")
            emit('status', {'message': 'Connected to Prashant918 Antivirus'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            self.logger.info("Client disconnected from WebSocket")
        
        @self.socketio.on('request_status')
        def handle_status_request():
            """Handle status request"""
            emit('system_status', {
                'components': self._get_components_status(),
                'stats': self.system_stats,
                'timestamp': datetime.now().isoformat()
            })
    
    def _get_components_status(self) -> Dict[str, bool]:
        """Get status of all components"""
        return {
            'threat_engine': self.threat_engine is not None,
            'quarantine_manager': self.quarantine_manager is not None,
            'realtime_monitor': self.realtime_monitor is not None,
            'signature_manager': self.signature_manager is not None,
            'service_manager': self.service_manager is not None
        }
    
    def _perform_file_scan(self, scan_id: str, file_path: str):
        """Perform file scan in background thread"""
        try:
            self.active_scans[scan_id]['status'] = 'scanning'
            self.active_scans[scan_id]['file_path'] = file_path
            
            # Perform scan
            result = self.threat_engine.scan_file(file_path)
            
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['result'] = result
            self.active_scans[scan_id]['progress'] = 100
            
            # Update stats
            self.system_stats['files_scanned'] += 1
            if result.get('status') == 'infected':
                self.system_stats['threats_detected'] += 1
            
            # Emit real-time update
            self.socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'result': result
            })
            
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'error'
            self.active_scans[scan_id]['error'] = str(e)
            self.logger.error(f"Scan error: {e}")
    
    def _perform_directory_scan(self, scan_id: str, directory_path: str, recursive: bool):
        """Perform directory scan in background thread"""
        try:
            self.active_scans[scan_id]['status'] = 'scanning'
            self.active_scans[scan_id]['directory_path'] = directory_path
            self.active_scans[scan_id]['results'] = []
            
            # Get list of files to scan
            path_obj = Path(directory_path)
            if recursive:
                files = list(path_obj.rglob('*'))
            else:
                files = list(path_obj.iterdir())
            
            files = [f for f in files if f.is_file()]
            total_files = len(files)
            
            self.active_scans[scan_id]['total_files'] = total_files
            
            for i, file_path in enumerate(files):
                try:
                    result = self.threat_engine.scan_file(str(file_path))
                    self.active_scans[scan_id]['results'].append(result)
                    
                    # Update progress
                    progress = int((i + 1) / total_files * 100)
                    self.active_scans[scan_id]['progress'] = progress
                    
                    # Update stats
                    self.system_stats['files_scanned'] += 1
                    if result.get('status') == 'infected':
                        self.system_stats['threats_detected'] += 1
                    
                    # Emit progress update
                    self.socketio.emit('scan_progress', {
                        'scan_id': scan_id,
                        'progress': progress,
                        'current_file': str(file_path)
                    })
                    
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
            
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['progress'] = 100
            
            # Emit completion
            self.socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'total_files': total_files,
                'results_count': len(self.active_scans[scan_id]['results'])
            })
            
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'error'
            self.active_scans[scan_id]['error'] = str(e)
            self.logger.error(f"Directory scan error: {e}")
    
    def _on_threat_detected(self, threat_info):
        """Handle threat detection from real-time monitor"""
        self.system_stats['threats_detected'] += 1
        
        # Emit real-time threat alert
        self.socketio.emit('threat_detected', {
            'threat': threat_info,
            'timestamp': datetime.now().isoformat()
        })
    
    def _start_background_tasks(self):
        """Start background tasks"""
        def update_stats():
            while True:
                try:
                    # Update system statistics
                    if self.quarantine_manager:
                        quarantined = self.quarantine_manager.list_quarantined_files()
                        self.system_stats['quarantined_files'] = len(quarantined)
                    
                    # Emit periodic status updates
                    self.socketio.emit('system_status', {
                        'stats': self.system_stats,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    time.sleep(30)  # Update every 30 seconds
                except Exception as e:
                    self.logger.error(f"Background task error: {e}")
                    time.sleep(60)
        
        threading.Thread(target=update_stats, daemon=True).start()
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Run the web application"""
        self.logger.info(f"Starting Prashant918 Antivirus Web GUI on http://{host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def create_app(config=None):
    """Factory function to create Flask app"""
    return AntivirusWebApp(config)

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
