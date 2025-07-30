"""
Prashant918 Advanced Antivirus - Enhanced ML Detector
Ensemble machine learning detector with multiple algorithms and cross-platform support
"""
import os
import sys
import time
import threading
import pickle
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging

# Core imports with error handling
try:
    from ..logger import SecureLogger
except ImportError:
    SecureLogger = logging.getLogger

try:
    from ..config import secure_config
except ImportError:
    secure_config = type('Config', (), {'get': lambda self, key, default=None: default})()

# ML imports with graceful degradation
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    RandomForestClassifier = None
    GradientBoostingClassifier = None
    VotingClassifier = None
    SVC = None
    MLPClassifier = None
    StandardScaler = None

try:
    import tensorflow as tf
    from tensorflow import keras
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    tf = None
    keras = None

class EnsembleMLDetector:
    """Enhanced ensemble ML detector with multiple algorithms"""
    
    def __init__(self):
        self.logger = SecureLogger("MLDetector")
        self.models = {}
        self.scaler = None
        self.neural_network = None
        self.is_trained = False
        self.model_lock = threading.Lock()
        
        # Model paths
        self.model_dir = Path("models")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.ensemble_model_path = self.model_dir / "ensemble_model.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.nn_model_path = self.model_dir / "neural_network.h5"
        
        # Performance metrics
        self.performance_metrics = {}
        
        # Feature extraction settings
        self.feature_size = 259  # Standard feature vector size
    
    def initialize(self) -> bool:
        """Initialize ML models"""
        try:
            self.logger.info("Initializing ML detector...")
            
            if not HAS_NUMPY:
                self.logger.error("NumPy not available - ML detection disabled")
                return False
            
            if not HAS_SKLEARN:
                self.logger.error("Scikit-learn not available - ML detection disabled")
                return False
            
            # Try to load existing models
            if self._load_models():
                self.logger.info("Loaded existing ML models")
                return True
            
            # Create and train new models if none exist
            self.logger.info("Creating new ML models...")
            self._create_models()
            
            # Train with synthetic data (in production, use real malware dataset)
            if self._train_with_sample_data():
                self._save_models()
                self.logger.info("ML models trained and saved")
                return True
            
            self.logger.warning("ML detector initialized without training data")
            return False
            
        except Exception as e:
            self.logger.error(f"ML detector initialization failed: {e}")
            return False
    
    def _create_models(self):
        """Create and configure ML models"""
        try:
            if not HAS_SKLEARN:
                return
            
            # Create individual models
            self.models = {
                'random_forest': RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                ),
                'gradient_boosting': GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=6,
                    random_state=42
                ),
                'svm': SVC(
                    kernel='rbf',
                    C=1.0,
                    gamma='scale',
                    probability=True,
                    random_state=42
                ),
                'mlp': MLPClassifier(
                    hidden_layer_sizes=(128, 64),
                    activation='relu',
                    solver='adam',
                    alpha=0.001,
                    batch_size='auto',
                    learning_rate='constant',
                    learning_rate_init=0.001,
                    max_iter=500,
                    random_state=42
                )
            }
            
            # Create ensemble model
            estimators = [(name, model) for name, model in self.models.items()]
            self.ensemble_model = VotingClassifier(
                estimators=estimators,
                voting='soft'
            )
            
            # Create scaler
            self.scaler = StandardScaler()
            
            # Create neural network if TensorFlow is available
            if HAS_TENSORFLOW:
                self._create_neural_network()
            
            self.logger.info("ML models created successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to create ML models: {e}")
            raise
    
    def _create_neural_network(self):
        """Create deep neural network"""
        if not HAS_TENSORFLOW:
            return
        
        try:
            self.neural_network = keras.Sequential([
                keras.layers.Dense(512, activation='relu', input_shape=(self.feature_size,)),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(256, activation='relu'),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(128, activation='relu'),
                keras.layers.Dropout(0.2),
                keras.layers.Dense(64, activation='relu'),
                keras.layers.Dense(1, activation='sigmoid')
            ])
            
            self.neural_network.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            self.logger.info("Neural network created successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to create neural network: {e}")
            self.neural_network = None
    
    def _train_with_sample_data(self) -> bool:
        """Train models with synthetic data"""
        try:
            if not HAS_SKLEARN or not HAS_NUMPY:
                return False
            
            self.logger.info("Generating synthetic training data...")
            X, y = self._generate_synthetic_data()
            
            if X is None or y is None:
                return False
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train ensemble model
            self.logger.info("Training ensemble model...")
            self.ensemble_model.fit(X_scaled, y)
            
            # Evaluate ensemble model
            cv_scores = cross_val_score(self.ensemble_model, X_scaled, y, cv=5)
            self.performance_metrics['ensemble_cv_score'] = cv_scores.mean()
            self.logger.info(f"Ensemble model CV score: {cv_scores.mean():.3f}")
            
            # Train neural network if available
            if self.neural_network and HAS_TENSORFLOW:
                self.logger.info("Training neural network...")
                history = self.neural_network.fit(
                    X_scaled, y,
                    epochs=50,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
                
                final_accuracy = history.history['accuracy'][-1]
                self.performance_metrics['nn_accuracy'] = final_accuracy
                self.logger.info(f"Neural network accuracy: {final_accuracy:.3f}")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            return False
    
    def _generate_synthetic_data(self) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Generate synthetic training data"""
        if not HAS_NUMPY:
            return None, None
        
        try:
            n_samples = 10000
            n_malicious = n_samples // 2
            n_benign = n_samples - n_malicious
            
            # Generate malicious samples (higher entropy, suspicious patterns)
            malicious_samples = []
            for _ in range(n_malicious):
                sample = np.random.random(self.feature_size)
                
                # Simulate malicious characteristics
                sample[0] = np.random.uniform(0.7, 1.0)  # High entropy
                sample[1] = np.random.uniform(0.6, 1.0)  # Suspicious strings
                sample[2] = np.random.uniform(0.5, 1.0)  # Packed executable
                sample[3:10] = np.random.uniform(0.4, 0.9, 7)  # API calls
                sample[10:20] = np.random.uniform(0.3, 0.8, 10)  # File operations
                
                # Add some noise
                sample += np.random.normal(0, 0.1, self.feature_size)
                sample = np.clip(sample, 0, 1)
                
                malicious_samples.append(sample)
            
            # Generate benign samples (lower entropy, normal patterns)
            benign_samples = []
            for _ in range(n_benign):
                sample = np.random.random(self.feature_size)
                
                # Simulate benign characteristics
                sample[0] = np.random.uniform(0.1, 0.5)  # Normal entropy
                sample[1] = np.random.uniform(0.0, 0.3)  # Few suspicious strings
                sample[2] = np.random.uniform(0.0, 0.2)  # Not packed
                sample[3:10] = np.random.uniform(0.0, 0.4, 7)  # Normal API calls
                sample[10:20] = np.random.uniform(0.0, 0.3, 10)  # Normal file ops
                
                # Add some noise
                sample += np.random.normal(0, 0.05, self.feature_size)
                sample = np.clip(sample, 0, 1)
                
                benign_samples.append(sample)
            
            # Combine samples
            X = np.vstack([malicious_samples, benign_samples])
            y = np.hstack([np.ones(n_malicious), np.zeros(n_benign)])
            
            # Shuffle data
            indices = np.random.permutation(len(X))
            X = X[indices]
            y = y[indices]
            
            self.logger.info(f"Generated {len(X)} synthetic samples")
            return X, y
            
        except Exception as e:
            self.logger.error(f"Synthetic data generation failed: {e}")
            return None, None
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict malware probability"""
        try:
            if not self.is_trained or not HAS_SKLEARN or not HAS_NUMPY:
                return {'probability': 0.0, 'prediction': 'unknown', 'confidence': 0.0}
            
            with self.model_lock:
                # Ensure features are the right shape
                if features.ndim == 1:
                    features = features.reshape(1, -1)
                
                # Pad or truncate features to expected size
                if features.shape[1] != self.feature_size:
                    if features.shape[1] < self.feature_size:
                        # Pad with zeros
                        padding = np.zeros((features.shape[0], self.feature_size - features.shape[1]))
                        features = np.hstack([features, padding])
                    else:
                        # Truncate
                        features = features[:, :self.feature_size]
                
                # Scale features
                features_scaled = self.scaler.transform(features)
                
                # Get ensemble prediction
                ensemble_prob = self.ensemble_model.predict_proba(features_scaled)[0][1]
                
                # Get neural network prediction if available
                nn_prob = 0.0
                if self.neural_network and HAS_TENSORFLOW:
                    try:
                        nn_prob = float(self.neural_network.predict(features_scaled, verbose=0)[0][0])
                    except Exception as e:
                        self.logger.debug(f"Neural network prediction failed: {e}")
                
                # Combine predictions (weighted average)
                if nn_prob > 0:
                    combined_prob = 0.6 * ensemble_prob + 0.4 * nn_prob
                else:
                    combined_prob = ensemble_prob
                
                # Determine prediction
                prediction = 'malicious' if combined_prob > 0.5 else 'benign'
                confidence = abs(combined_prob - 0.5) * 2  # Convert to 0-1 confidence
                
                return {
                    'probability': float(combined_prob),
                    'prediction': prediction,
                    'confidence': float(confidence),
                    'ensemble_prob': float(ensemble_prob),
                    'nn_prob': float(nn_prob) if nn_prob > 0 else None
                }
                
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            return {'probability': 0.0, 'prediction': 'error', 'confidence': 0.0}
    
    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """Extract features from file for ML analysis"""
        try:
            if not HAS_NUMPY:
                return None
            
            features = []
            file_path = Path(file_path)
            
            # File size features
            try:
                file_size = file_path.stat().st_size
                features.extend([
                    min(file_size / (1024 * 1024), 100),  # Size in MB, capped at 100
                    1.0 if file_size == 0 else 0.0,  # Zero-byte file
                    1.0 if file_size > 50 * 1024 * 1024 else 0.0  # Large file (>50MB)
                ])
            except OSError:
                features.extend([0.0, 0.0, 0.0])
            
            # File extension features
            ext_features = self._extract_extension_features(file_path)
            
            features.extend(ext_features)
            
            # Entropy and byte distribution features
            entropy_features = self._extract_entropy_features(file_path)
            features.extend(entropy_features)
            
            # String analysis features
            string_features = self._extract_string_features(file_path)
            features.extend(string_features)
            
            # Header analysis features
            header_features = self._extract_header_features(file_path)
            features.extend(header_features)
            
            # Pad or truncate to expected feature size
            while len(features) < self.feature_size:
                features.append(0.0)
            
            features = features[:self.feature_size]
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed for {file_path}: {e}")
            return None
    
    def _extract_extension_features(self, file_path: Path) -> List[float]:
        """Extract file extension features"""
        try:
            ext = file_path.suffix.lower()
            
            # Extension categories
            executable_exts = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif'}
            script_exts = {'.js', '.vbs', '.ps1', '.py', '.pl', '.sh'}
            archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz'}
            document_exts = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}
            
            return [
                1.0 if ext in executable_exts else 0.0,
                1.0 if ext in script_exts else 0.0,
                1.0 if ext in archive_exts else 0.0,
                1.0 if ext in document_exts else 0.0,
                1.0 if '.' not in file_path.name else 0.0,  # No extension
                float(file_path.name.count('.'))  # Multiple extensions
            ]
        except Exception:
            return [0.0] * 6
    
    def _extract_entropy_features(self, file_path: Path) -> List[float]:
        """Extract entropy and byte distribution features"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB
            
            if not data:
                return [0.0] * 10
            
            # Calculate entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            # Byte distribution features
            null_bytes = byte_counts[0] / data_len
            printable_bytes = sum(byte_counts[32:127]) / data_len
            high_bytes = sum(byte_counts[128:]) / data_len
            
            # Statistical features
            mean_byte = sum(i * count for i, count in enumerate(byte_counts)) / data_len
            
            return [
                min(entropy / 8.0, 1.0),  # Normalized entropy
                null_bytes,
                printable_bytes,
                high_bytes,
                mean_byte / 255.0,
                1.0 if entropy > 7.5 else 0.0,  # High entropy flag
                1.0 if entropy < 1.0 else 0.0,  # Low entropy flag
                1.0 if null_bytes > 0.5 else 0.0,  # Many null bytes
                1.0 if printable_bytes < 0.1 else 0.0,  # Few printable bytes
                1.0 if high_bytes > 0.3 else 0.0  # Many high bytes
            ]
            
        except Exception:
            return [0.0] * 10
    
    def _extract_string_features(self, file_path: Path) -> List[float]:
        """Extract string-based features"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(16384)  # Read first 16KB
            
            if not data:
                return [0.0] * 20
            
            # Extract strings
            strings = []
            current_string = ""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            if len(current_string) >= 4:
                strings.append(current_string)
            
            # String statistics
            total_strings = len(strings)
            avg_length = sum(len(s) for s in strings) / max(total_strings, 1)
            max_length = max((len(s) for s in strings), default=0)
            
            # Suspicious string patterns
            suspicious_keywords = [
                'password', 'admin', 'root', 'hack', 'crack', 'keygen',
                'backdoor', 'trojan', 'virus', 'malware', 'payload',
                'shell', 'cmd', 'exec', 'system', 'registry'
            ]
            
            api_calls = [
                'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
                'CreateProcess', 'TerminateProcess', 'OpenProcess',
                'VirtualAlloc', 'VirtualProtect', 'LoadLibrary'
            ]
            
            network_apis = [
                'InternetOpen', 'InternetConnect', 'HttpSendRequest',
                'WSAStartup', 'socket', 'connect', 'send', 'recv'
            ]
            
            crypto_apis = [
                'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
                'CryptAcquireContext', 'CryptCreateHash'
            ]
            
            # Count suspicious patterns
            suspicious_count = sum(1 for s in strings if any(
                keyword.lower() in s.lower() for keyword in suspicious_keywords
            ))
            
            api_count = sum(1 for s in strings if any(
                api in s for api in api_calls
            ))
            
            network_count = sum(1 for s in strings if any(
                api in s for api in network_apis
            ))
            
            crypto_count = sum(1 for s in strings if any(
                api in s for api in crypto_apis
            ))
            
            # URL and email patterns
            url_count = sum(1 for s in strings if 'http' in s.lower() or 'www.' in s.lower())
            email_count = sum(1 for s in strings if '@' in s and '.' in s)
            
            return [
                min(total_strings / 100.0, 1.0),  # Normalized string count
                min(avg_length / 50.0, 1.0),  # Normalized average length
                min(max_length / 200.0, 1.0),  # Normalized max length
                min(suspicious_count / max(total_strings, 1), 1.0),  # Suspicious ratio
                min(api_count / max(total_strings, 1), 1.0),  # API call ratio
                min(network_count / max(total_strings, 1), 1.0),  # Network API ratio
                min(crypto_count / max(total_strings, 1), 1.0),  # Crypto API ratio
                min(url_count / max(total_strings, 1), 1.0),  # URL ratio
                min(email_count / max(total_strings, 1), 1.0),  # Email ratio
                1.0 if total_strings == 0 else 0.0,  # No strings flag
                1.0 if avg_length > 100 else 0.0,  # Long strings flag
                1.0 if suspicious_count > 5 else 0.0,  # Many suspicious strings
                1.0 if api_count > 10 else 0.0,  # Many API calls
                1.0 if network_count > 3 else 0.0,  # Network activity
                1.0 if crypto_count > 2 else 0.0,  # Crypto activity
                1.0 if url_count > 5 else 0.0,  # Many URLs
                1.0 if any(len(s) > 500 for s in strings) else 0.0,  # Very long strings
                1.0 if any(s.isupper() and len(s) > 20 for s in strings) else 0.0,  # All caps
                1.0 if any(s.isdigit() and len(s) > 10 for s in strings) else 0.0,  # Long numbers
                1.0 if any(not s.isascii() for s in strings) else 0.0  # Non-ASCII strings
            ]
            
        except Exception:
            return [0.0] * 20
    
    def _extract_header_features(self, file_path: Path) -> List[float]:
        """Extract file header features"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)  # Read first 512 bytes
            
            if not header:
                return [0.0] * 15
            
            features = []
            
            # Magic number detection
            magic_signatures = {
                b'MZ': 1.0,  # PE executable
                b'PK': 2.0,  # ZIP archive
                b'\x7fELF': 3.0,  # ELF executable
                b'%PDF': 4.0,  # PDF document
                b'\x89PNG': 5.0,  # PNG image
                b'GIF8': 6.0,  # GIF image
                b'\xff\xd8\xff': 7.0,  # JPEG image
            }
            
            magic_type = 0.0
            for signature, type_id in magic_signatures.items():
                if header.startswith(signature):
                    magic_type = type_id
                    break
            
            features.append(magic_type / 7.0)  # Normalized magic type
            
            # PE-specific features
            if header.startswith(b'MZ'):
                try:
                    # Check for PE signature
                    pe_offset = int.from_bytes(header[60:64], 'little')
                    features.extend([
                        1.0,  # Is PE file
                        1.0 if pe_offset > len(header) else 0.0,  # Invalid PE offset
                        1.0 if b'This program cannot be run in DOS mode' in header else 0.0
                    ])
                except:
                    features.extend([1.0, 0.0, 0.0])
            else:
                features.extend([0.0, 0.0, 0.0])
            
            # General header features
            null_ratio = header.count(0) / len(header)
            printable_ratio = sum(1 for b in header if 32 <= b <= 126) / len(header)
            
            features.extend([
                null_ratio,
                printable_ratio,
                1.0 if null_ratio > 0.8 else 0.0,  # Mostly null bytes
                1.0 if printable_ratio < 0.1 else 0.0,  # Few printable bytes
                1.0 if len(set(header)) < 10 else 0.0,  # Low byte diversity
                min(len(set(header)) / 256.0, 1.0),  # Byte diversity ratio
                1.0 if header[:4] == b'\x00' * 4 else 0.0,  # Starts with nulls
                1.0 if header[-4:] == b'\x00' * 4 else 0.0,  # Ends with nulls
                1.0 if b'\x00' * 10 in header else 0.0,  # Long null sequences
                1.0 if b'\xff' * 10 in header else 0.0,  # Long 0xFF sequences
                1.0 if any(header[i:i+2] == b'\x90\x90' for i in range(len(header)-1)) else 0.0  # NOP sleds
            ])
            
            return features
            
        except Exception:
            return [0.0] * 15
    
    def analyze_behavioral_patterns(self, file_path: str, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns using ML"""
        try:
            features = self.extract_features(file_path)
            if features is None:
                return {'score': 0.0, 'prediction': 'unknown', 'confidence': 0.0}
            
            prediction_result = self.predict(features)
            
            return {
                'score': prediction_result['probability'],
                'prediction': prediction_result['prediction'],
                'confidence': prediction_result['confidence'],
                'ml_analysis': prediction_result,
                'feature_count': len(features)
            }
            
        except Exception as e:
            self.logger.error(f"Behavioral pattern analysis failed: {e}")
            return {'score': 0.0, 'prediction': 'error', 'confidence': 0.0}
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            with self.model_lock:
                if HAS_SKLEARN and self.ensemble_model and self.scaler:
                    # Save ensemble model
                    joblib.dump(self.ensemble_model, self.ensemble_model_path)
                    
                    # Save scaler
                    joblib.dump(self.scaler, self.scaler_path)
                    
                    self.logger.info("Ensemble model and scaler saved")
                
                # Save neural network
                if self.neural_network and HAS_TENSORFLOW:
                    self.neural_network.save(self.nn_model_path)
                    self.logger.info("Neural network saved")
                
                # Save performance metrics
                metrics_path = self.model_dir / "performance_metrics.pkl"
                with open(metrics_path, 'wb') as f:
                    pickle.dump(self.performance_metrics, f)
                
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def _load_models(self) -> bool:
        """Load trained models from disk"""
        try:
            with self.model_lock:
                # Load ensemble model and scaler
                if (self.ensemble_model_path.exists() and 
                    self.scaler_path.exists() and HAS_SKLEARN):
                    
                    self.ensemble_model = joblib.load(self.ensemble_model_path)
                    self.scaler = joblib.load(self.scaler_path)
                    self.is_trained = True
                    self.logger.info("Ensemble model and scaler loaded")
                else:
                    return False
                
                # Load neural network
                if self.nn_model_path.exists() and HAS_TENSORFLOW:
                    try:
                        self.neural_network = keras.models.load_model(self.nn_model_path)
                        self.logger.info("Neural network loaded")
                    except Exception as e:
                        self.logger.warning(f"Failed to load neural network: {e}")
                
                # Load performance metrics
                metrics_path = self.model_dir / "performance_metrics.pkl"
                if metrics_path.exists():
                    try:
                        with open(metrics_path, 'rb') as f:
                            self.performance_metrics = pickle.load(f)
                    except Exception as e:
                        self.logger.warning(f"Failed to load performance metrics: {e}")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")
            return False
    
    def update_models(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Update models with new training data"""
        try:
            if not self.is_trained or not HAS_SKLEARN or not HAS_NUMPY:
                return False
            
            with self.model_lock:
                # Scale new data
                X_scaled = self.scaler.transform(X)
                
                # Update ensemble model (retrain)
                self.ensemble_model.fit(X_scaled, y)
                
                # Update neural network
                if self.neural_network and HAS_TENSORFLOW:
                    self.neural_network.fit(
                        X_scaled, y,
                        epochs=10,
                        batch_size=32,
                        verbose=0
                    )
                
                # Save updated models
                self._save_models()
                
                self.logger.info(f"Models updated with {len(X)} new samples")
                return True
                
        except Exception as e:
            self.logger.error(f"Model update failed: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if ML detector is initialized"""
        return self.is_trained
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        info = {
            'is_trained': self.is_trained,
            'has_sklearn': HAS_SKLEARN,
            'has_tensorflow': HAS_TENSORFLOW,
            'has_numpy': HAS_NUMPY,
            'feature_size': self.feature_size,
            'models_available': []
        }
        
        if HAS_SKLEARN and hasattr(self, 'ensemble_model'):
            info['models_available'].append('ensemble')
        
        if self.neural_network:
            info['models_available'].append('neural_network')
        
        if self.performance_metrics:
            info['performance_metrics'] = self.performance_metrics
        
        return info
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get ML detector statistics"""
        return {
            'is_initialized': self.is_initialized(),
            'model_info': self.get_model_info(),
            'feature_size': self.feature_size,
            'model_files_exist': {
                'ensemble': self.ensemble_model_path.exists(),
                'scaler': self.scaler_path.exists(),
                'neural_network': self.nn_model_path.exists()
            }
        }

# Backward compatibility
class EnsembleMLDetector(EnsembleMLDetector):
    """Alias for backward compatibility"""
    pass
