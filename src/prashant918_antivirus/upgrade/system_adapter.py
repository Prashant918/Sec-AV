"""
System Adaptation Manager
Handles adaptive degradation based on system device capabilities
"""

import psutil
import platform
import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import subprocess

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import AntivirusError


class DeviceClass(Enum):
    """Device classification based on capabilities"""
    HIGH_END = "high_end"
    MEDIUM_END = "medium_end"
    LOW_END = "low_end"
    EMBEDDED = "embedded"


class PerformanceProfile(Enum):
    """Performance profiles for different device classes"""
    MAXIMUM = "maximum"
    BALANCED = "balanced"
    CONSERVATIVE = "conservative"
    MINIMAL = "minimal"


@dataclass
class SystemCapabilities:
    """System capability information"""
    cpu_cores: int
    cpu_frequency_mhz: float
    total_memory_gb: float
    available_memory_gb: float
    disk_free_gb: float
    disk_type: str  # SSD, HDD, etc.
    platform: str
    architecture: str
    battery_powered: bool
    network_type: str  # wifi, ethernet, cellular, etc.
    gpu_available: bool
    device_class: DeviceClass
    performance_score: float


class SystemAdapter:
    """
    Manages system adaptation and performance degradation based on device capabilities
    """
    
    def __init__(self):
        self.logger = SecureLogger("SystemAdapter")
        self.config = SecureConfig()
        
        # System monitoring
        self.capabilities: Optional[SystemCapabilities] = None
        self.current_profile = PerformanceProfile.BALANCED
        self.monitoring_enabled = True
        self.monitor_thread = None
        self.monitor_interval = 30  # seconds
        
        # Adaptation settings
        self.auto_adaptation_enabled = self.config.get('system.auto_adaptation', True)
        self.adaptation_sensitivity = self.config.get('system.adaptation_sensitivity', 0.7)
        
        # Performance thresholds
        self.thresholds = {
            'memory_usage_critical': 0.9,
            'memory_usage_high': 0.8,
            'cpu_usage_critical': 0.9,
            'cpu_usage_high': 0.8,
            'disk_space_critical': 0.95,
            'disk_space_low': 0.85,
            'battery_critical': 0.15,
            'battery_low': 0.25
        }
        
        # Feature configurations for different profiles
        self.profile_configs = self._load_profile_configurations()
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Initialize system capabilities
        self._detect_system_capabilities()
        
    def _load_profile_configurations(self) -> Dict[PerformanceProfile, Dict]:
        """Load configuration for different performance profiles"""
        return {
            PerformanceProfile.MAXIMUM: {
                'scanning': {
                    'parallel_threads': 8,
                    'max_file_size_mb': 500,
                    'deep_scan_enabled': True,
                    'ml_detection_enabled': True,
                    'behavioral_analysis_enabled': True,
                    'yara_rules_enabled': True,
                    'cloud_intelligence_enabled': True,
                    'memory_scanner_enabled': True,
                    'network_scanner_enabled': True
                },
                'realtime_monitoring': {
                    'enabled': True,
                    'scan_frequency_ms': 100,
                    'monitor_all_extensions': True,
                    'process_monitoring_enabled': True,
                    'network_monitoring_enabled': True,
                    'memory_monitoring_enabled': True
                },
                'updates': {
                    'check_interval_hours': 1,
                    'auto_update_enabled': True,
                    'signature_updates_enabled': True,
                    'ml_model_updates_enabled': True
                },
                'logging': {
                    'level': 'DEBUG',
                    'detailed_logs': True,
                    'performance_logging': True
                }
            },
            PerformanceProfile.BALANCED: {
                'scanning': {
                    'parallel_threads': 4,
                    'max_file_size_mb': 200,
                    'deep_scan_enabled': True,
                    'ml_detection_enabled': True,
                    'behavioral_analysis_enabled': True,
                    'yara_rules_enabled': True,
                    'cloud_intelligence_enabled': True,
                    'memory_scanner_enabled': False,
                    'network_scanner_enabled': False
                },
                'realtime_monitoring': {
                    'enabled': True,
                    'scan_frequency_ms': 500,
                    'monitor_all_extensions': False,
                    'process_monitoring_enabled': True,
                    'network_monitoring_enabled': False,
                    'memory_monitoring_enabled': False
                },
                'updates': {
                    'check_interval_hours': 4,
                    'auto_update_enabled': True,
                    'signature_updates_enabled': True,
                    'ml_model_updates_enabled': False
                },
                'logging': {
                    'level': 'INFO',
                    'detailed_logs': False,
                    'performance_logging': False
                }
            },
            PerformanceProfile.CONSERVATIVE: {
                'scanning': {
                    'parallel_threads': 2,
                    'max_file_size_mb': 100,
                    'deep_scan_enabled': False,
                    'ml_detection_enabled': True,
                    'behavioral_analysis_enabled': False,
                    'yara_rules_enabled': True,
                    'cloud_intelligence_enabled': False,
                    'memory_scanner_enabled': False,
                    'network_scanner_enabled': False
                },
                'realtime_monitoring': {
                    'enabled': True,
                    'scan_frequency_ms': 2000,
                    'monitor_all_extensions': False,
                    'process_monitoring_enabled': False,
                    'network_monitoring_enabled': False,
                    'memory_monitoring_enabled': False
                },
                'updates': {
                    'check_interval_hours': 12,
                    'auto_update_enabled': True,
                    'signature_updates_enabled': True,
                    'ml_model_updates_enabled': False
                },
                'logging': {
                    'level': 'WARNING',
                    'detailed_logs': False,
                    'performance_logging': False
                }
            },
            PerformanceProfile.MINIMAL: {
                'scanning': {
                    'parallel_threads': 1,
                    'max_file_size_mb': 50,
                    'deep_scan_enabled': False,
                    'ml_detection_enabled': False,
                    'behavioral_analysis_enabled': False,
                    'yara_rules_enabled': True,
                    'cloud_intelligence_enabled': False,
                    'memory_scanner_enabled': False,
                    'network_scanner_enabled': False
                },
                'realtime_monitoring': {
                    'enabled': False,
                    'scan_frequency_ms': 5000,
                    'monitor_all_extensions': False,
                    'process_monitoring_enabled': False,
                    'network_monitoring_enabled': False,
                    'memory_monitoring_enabled': False
                },
                'updates': {
                    'check_interval_hours': 24,
                    'auto_update_enabled': False,
                    'signature_updates_enabled': True,
                    'ml_model_updates_enabled': False
                },
                'logging': {
                    'level': 'ERROR',
                    'detailed_logs': False,
                    'performance_logging': False
                }
            }
        }
        
    def _detect_system_capabilities(self) -> None:
        """Detect and analyze system capabilities"""
        try:
            self.logger.info("Detecting system capabilities...")
            
            # CPU information
            cpu_cores = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            cpu_frequency_mhz = cpu_freq.current if cpu_freq else 0.0
            
            # Memory information
            memory = psutil.virtual_memory()
            total_memory_gb = memory.total / (1024**3)
            available_memory_gb = memory.available / (1024**3)
            
            # Disk information
            disk = psutil.disk_usage('/')
            disk_free_gb = disk.free / (1024**3)
            disk_type = self._detect_disk_type()
            
            # Platform information
            system_platform = platform.system()
            architecture = platform.machine()
            
            # Battery information
            battery_powered = self._is_battery_powered()
            
            # Network information
            network_type = self._detect_network_type()
            
            # GPU information
            gpu_available = self._detect_gpu()
            
            # Calculate performance score
            performance_score = self._calculate_performance_score(
                cpu_cores, cpu_frequency_mhz,
                total_memory_gb, disk_type, gpu_available
            )
            
            # Determine device class
            device_class = self._classify_device(performance_score, total_memory_gb, cpu_cores)
            
            self.capabilities = SystemCapabilities(
                cpu_cores=cpu_cores,
                cpu_frequency_mhz=cpu_frequency_mhz,
                total_memory_gb=total_memory_gb,
                available_memory_gb=available_memory_gb,
                disk_free_gb=disk_free_gb,
                disk_type=disk_type,
                platform=system_platform,
                architecture=architecture,
                battery_powered=battery_powered,
                network_type=network_type,
                gpu_available=gpu_available,
                device_class=device_class,
                performance_score=performance_score
            )
            
            # Set initial performance profile based on device class
            self._set_initial_profile()
            
            self.logger.info(f"System capabilities detected: {device_class.value} device "
                           f"(score: {performance_score:.2f})")
            
        except Exception as e:
            self.logger.error(f"Failed to detect system capabilities: {e}")
            # Set minimal capabilities as fallback
            self.capabilities = SystemCapabilities(
                cpu_cores=1, cpu_frequency_mhz=1000.0, total_memory_gb=2.0,
                available_memory_gb=1.0, disk_free_gb=10.0, disk_type="HDD",
                platform="Unknown", architecture="Unknown", battery_powered=False,
                network_type="unknown", gpu_available=False,
                device_class=DeviceClass.LOW_END, performance_score=0.3
            )
            
    def _detect_disk_type(self) -> str:
        """Detect disk type (SSD/HDD)"""
        try:
            # Try to detect SSD on different platforms
            if platform.system() == "Linux":
                try:
                    result = subprocess.run(['lsblk', '-d', '-o', 'name,rota'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and '0' in result.stdout:
                        return "SSD"
                except:
                    pass
                    
            elif platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'diskdrive', 'get', 'MediaType'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and 'SSD' in result.stdout:
                        return "SSD"
                except:
                    pass
                    
            elif platform.system() == "Darwin":  # macOS
                try:
                    result = subprocess.run(['system_profiler', 'SPSerialATADataType'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and 'Solid State' in result.stdout:
                        return "SSD"
                except:
                    pass
                    
            return "HDD"  # Default assumption
            
        except Exception as e:
            self.logger.debug(f"Could not detect disk type: {e}")
            return "Unknown"
            
    def _is_battery_powered(self) -> bool:
        """Check if system is battery powered"""
        try:
            battery = psutil.sensors_battery()
            return battery is not None
        except Exception:
            return False
            
    def _detect_network_type(self) -> str:
        """Detect primary network connection type"""
        try:
            # This is a simplified detection
            # In practice, you'd check active network interfaces
            network_stats = psutil.net_if_stats()
            
            # Look for common interface names
            for interface, stats in network_stats.items():
                if stats.isup:
                    interface_lower = interface.lower()
                    if 'wifi' in interface_lower or 'wlan' in interface_lower:
                        return "wifi"
                    elif 'eth' in interface_lower or 'lan' in interface_lower:
                        return "ethernet"
                        
            return "unknown"
            
        except Exception as e:
            self.logger.debug(f"Could not detect network type: {e}")
            return "unknown"
            
    def _detect_gpu(self) -> bool:
        """Detect if GPU is available"""
        try:
            # Try to detect GPU on different platforms
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'path', 'win32_VideoController', 'get', 'name'], 
                                          capture_output=True, text=True, timeout=5)
                    return result.returncode == 0 and len(result.stdout.strip().split('\n')) > 2
                except:
                    pass
                    
            elif platform.system() == "Linux":
                try:
                    result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
                    return result.returncode == 0 and 'VGA' in result.stdout
                except:
                    pass
                    
            elif platform.system() == "Darwin":  # macOS
                try:
                    result = subprocess.run(['system_profiler', 'SPDisplaysDataType'], 
                                          capture_output=True, text=True, timeout=5)
                    return result.returncode == 0 and 'Chipset Model' in result.stdout
                except:
                    pass
                    
            return False
            
        except Exception as e:
            self.logger.debug(f"Could not detect GPU: {e}")
            return False
            
    def _calculate_performance_score(self, cpu_cores: int, cpu_freq: float, 
                                   memory_gb: float, disk_type: str, gpu_available: bool) -> float:
        """Calculate overall system performance score (0.0 to 1.0)"""
        try:
            score = 0.0
            
            # CPU score (40% weight)
            cpu_score = min(cpu_cores / 8.0, 1.0) * 0.6 + min(cpu_freq / 3000.0, 1.0) * 0.4
            score += cpu_score * 0.4
            
            # Memory score (30% weight)
            memory_score = min(memory_gb / 16.0, 1.0)
            score += memory_score * 0.3
            
            # Disk score (20% weight)
            disk_score = 0.8 if disk_type == "SSD" else 0.4
            score += disk_score * 0.2
            
            # GPU bonus (10% weight)
            gpu_score = 1.0 if gpu_available else 0.0
            score += gpu_score * 0.1
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating performance score: {e}")
            return 0.5  # Default middle score
            
    def _classify_device(self, performance_score: float, memory_gb: float, cpu_cores: int) -> DeviceClass:
        """Classify device based on capabilities"""
        try:
            if performance_score >= 0.8 and memory_gb >= 8 and cpu_cores >= 4:
                return DeviceClass.HIGH_END
            elif performance_score >= 0.6 and memory_gb >= 4 and cpu_cores >= 2:
                return DeviceClass.MEDIUM_END
            elif performance_score >= 0.3 and memory_gb >= 2:
                return DeviceClass.LOW_END
            else:
                return DeviceClass.EMBEDDED
                
        except Exception as e:
            self.logger.error(f"Error classifying device: {e}")
            return DeviceClass.LOW_END
            
    def _set_initial_profile(self) -> None:
        """Set initial performance profile based on device class"""
        try:
            if not self.capabilities:
                return
                
            device_class = self.capabilities.device_class
            
            if device_class == DeviceClass.HIGH_END:
                self.current_profile = PerformanceProfile.MAXIMUM
            elif device_class == DeviceClass.MEDIUM_END:
                self.current_profile = PerformanceProfile.BALANCED
            elif device_class == DeviceClass.LOW_END:
                self.current_profile = PerformanceProfile.CONSERVATIVE
            else:  # EMBEDDED
                self.current_profile = PerformanceProfile.MINIMAL
                
            self.logger.info(f"Initial performance profile set to: {self.current_profile.value}")
            
        except Exception as e:
            self.logger.error(f"Error setting initial profile: {e}")
            self.current_profile = PerformanceProfile.CONSERVATIVE
            
    def start_monitoring(self) -> None:
        """Start system monitoring for adaptive performance"""
        try:
            if not self.auto_adaptation_enabled:
                self.logger.info("Auto-adaptation disabled, monitoring not started")
                return
                
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.logger.warning("System monitoring already running")
                return
                
            self.monitoring_enabled = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
            
            self.logger.info("System monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start system monitoring: {e}")
            
    def stop_monitoring(self) -> None:
        """Stop system monitoring"""
        try:
            self.monitoring_enabled = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
                
            self.logger.info("System monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping system monitoring: {e}")
            
    def _monitoring_loop(self) -> None:
        """Main monitoring loop for adaptive performance"""
        while self.monitoring_enabled:
            try:
                # Check system resources
                current_state = self._get_current_system_state()
                
                # Determine if profile change is needed
                recommended_profile = self._recommend_profile(current_state)
                
                # Apply profile change if needed
                if recommended_profile != self.current_profile:
                    self._change_performance_profile(recommended_profile, 
                                                   f"System state change: {current_state}")
                    
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait longer on error
                
    def _get_current_system_state(self) -> Dict[str, Any]:
        """Get current system resource state"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Battery state (if applicable)
            battery_percent = None
            if self.capabilities and self.capabilities.battery_powered:
                battery = psutil.sensors_battery()
                if battery:
                    battery_percent = battery.percent
                    
            # Process count
            process_count = len(psutil.pids())
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'battery_percent': battery_percent,
                'process_count': process_count,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system state: {e}")
            return {}
            
    def _recommend_profile(self, system_state: Dict[str, Any]) -> PerformanceProfile:
        """Recommend performance profile based on system state"""
        try:
            cpu_percent = system_state.get('cpu_percent', 0)
            memory_percent = system_state.get('memory_percent', 0)
            battery_percent = system_state.get('battery_percent')
            
            # Critical resource conditions - force minimal profile
            if (memory_percent > self.thresholds['memory_usage_critical'] * 100 or
                cpu_percent > self.thresholds['cpu_usage_critical'] * 100 or
                (battery_percent and battery_percent < self.thresholds['battery_critical'] * 100)):
                return PerformanceProfile.MINIMAL
                
            # High resource usage - use conservative profile
            if (memory_percent > self.thresholds['memory_usage_high'] * 100 or
                cpu_percent > self.thresholds['cpu_usage_high'] * 100 or
                (battery_percent and battery_percent < self.thresholds['battery_low'] * 100)):
                return PerformanceProfile.CONSERVATIVE
                
            # Normal conditions - use profile based on device class
            if not self.capabilities:
                return PerformanceProfile.BALANCED
                
            device_class = self.capabilities.device_class
            
            if device_class == DeviceClass.HIGH_END and cpu_percent < 50 and memory_percent < 60:
                return PerformanceProfile.MAXIMUM
            elif device_class in [DeviceClass.HIGH_END, DeviceClass.MEDIUM_END]:
                return PerformanceProfile.BALANCED
            else:
                return PerformanceProfile.CONSERVATIVE
                
        except Exception as e:
            self.logger.error(f"Error recommending profile: {e}")
            return PerformanceProfile.CONSERVATIVE
            
    def _change_performance_profile(self, new_profile: PerformanceProfile, reason: str) -> None:
        """Change the current performance profile"""
        try:
            with self.lock:
                old_profile = self.current_profile
                self.current_profile = new_profile
                
                # Apply new configuration
                self._apply_profile_configuration(new_profile)
                
                self.logger.info(f"Performance profile changed from {old_profile.value} "
                               f"to {new_profile.value}. Reason: {reason}")
                
        except Exception as e:
            self.logger.error(f"Error changing performance profile: {e}")
            
    def _apply_profile_configuration(self, profile: PerformanceProfile) -> None:
        """Apply configuration for the specified profile"""
        try:
            config = self.profile_configs.get(profile, {})
            
            # Update configuration in SecureConfig
            for section, settings in config.items():
                for key, value in settings.items():
                    config_key = f"{section}.{key}"
                    self.config.set(config_key, value)
                    
            self.logger.debug(f"Applied configuration for profile: {profile.value}")
            
        except Exception as e:
            self.logger.error(f"Error applying profile configuration: {e}")
            
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        try:
            info = {
                'capabilities': {
                    'cpu_cores': self.capabilities.cpu_cores if self.capabilities else 0,
                    'cpu_frequency_mhz': self.capabilities.cpu_frequency_mhz if self.capabilities else 0,
                    'total_memory_gb': self.capabilities.total_memory_gb if self.capabilities else 0,
                    'disk_type': self.capabilities.disk_type if self.capabilities else "Unknown",
                    'platform': self.capabilities.platform if self.capabilities else "Unknown",
                    'device_class': self.capabilities.device_class.value if self.capabilities else "unknown",
                    'performance_score': self.capabilities.performance_score if self.capabilities else 0,
                    'battery_powered': self.capabilities.battery_powered if self.capabilities else False,
                    'gpu_available': self.capabilities.gpu_available if self.capabilities else False
                },
                'current_profile': self.current_profile.value,
                'monitoring_enabled': self.monitoring_enabled,
                'auto_adaptation_enabled': self.auto_adaptation_enabled,
                'current_state': self._get_current_system_state()
            }
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {}
            
    def force_profile_change(self, profile: PerformanceProfile) -> bool:
        """Force a change to a specific performance profile"""
        try:
            self._change_performance_profile(profile, "Manual override")
            return True
        except Exception as e:
            self.logger.error(f"Error forcing profile change: {e}")
            return False
            
    def get_available_profiles(self) -> List[str]:
        """Get list of available performance profiles"""
        return [profile.value for profile in PerformanceProfile]
        
    def get_profile_configuration(self, profile: PerformanceProfile) -> Dict[str, Any]:
        """Get configuration for a specific profile"""
        return self.profile_configs.get(profile, {})