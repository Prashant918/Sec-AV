"""
Prashant918 Advanced Antivirus - Enhanced ML Detector
Machine learning-based malware detection with ensemble methods
"""

import os
import sys
import time
import threading
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import numpy as np

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

# Optional ML imports with proper error handling
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier
    from sklearn.ensemble import VotingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import accuracy_score, classification_report
    import sklearn
    HAS_SKLEARN = True
    SKLEARN_VERSION = sklearn.__version__
except ImportError:
    HAS_SKLEARN = False
    SKLEARN_VERSION = None
    IsolationForest = None
    RandomForestClassifier = None
    GradientBoostingClassifier = None
    SVC = None
    MLPClassifier = None
    VotingClassifier = None
    StandardScaler = None
    cross_val_score = None

try:
    import tensorflow as tf
    from tensorflow import keras
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    tf = None
    keras = None

class EnsembleMLDetector:
    """
    Enhanced ML detector with ensemble methods and proper error handling
    """
    
    def __init__(self):
        self.logger = SecureLogger("MLDetector")
        self.models = None
        self.scaler = None
        self.neural_network = None
        self.anomaly_detector = None
        self.model_lock = threading.Lock()
        self.initialized = False
        
        # Model paths
        self.models_dir = Path.home() / ".prashant918_antivirus" / "models"
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Feature configuration
        self.feature_size = 259
        
        # Model performance tracking
        self.model_stats = {
            'ensemble_accuracy': 0.0,
            'neural_network_accuracy': 0.0,
            'anomaly_detector_accuracy': 0.0,
            'last_training': None,
            'predictions_made': 0,
            'sklearn_version': SKLEARN_VERSION
        }
        
        # Check dependencies
        if not HAS_NUMPY:
            self.logger.warning("NumPy not available - ML detection disabled")
        if not HAS_SKLEARN:
            self.logger.warning("Scikit-learn not available - ensemble methods disabled")
        if not HAS_TENSORFLOW:
            self.logger.warning("TensorFlow not available - neural network disabled")
        
        if HAS_SKLEARN:
            self.logger.info(f"Using scikit-learn version: {SKLEARN_VERSION}")

    def initialize(self) -> bool:
        """Initialize ML models with proper error handling"""
        try:
            if not HAS_NUMPY or not HAS_SKLEARN:
                self.logger.warning("Required ML dependencies not available")
                return False
            
            self.logger.info("Initializing ML detector...")
            
            # Try to load existing models first
            if self._load_models():
                self.logger.info("Loaded existing ML models")
                self.initialized = True
                return True
            
            # Create new models if loading failed
            self._create_models()
            
            # Train with sample data
            self._train_with_sample_data()
            
            # Save models
            self._save_models()
            
            self.initialized = True
            self.logger.info("ML detector initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"ML detector initialization failed: {e}")
            return False

    def _create_models(self):
        """Create ensemble models with proper error handling"""
        try:
            if not HAS_SKLEARN:
                self.logger.warning("Scikit-learn not available, skipping model creation")
                return
            
            self.logger.info("Creating ML models...")
            
            # Create individual models with error handling
            models = []
            
            try:
                rf = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                )
                models.append(('rf', rf))
                self.logger.debug("RandomForest model created")
            except Exception as e:
                self.logger.warning(f"Failed to create RandomForest: {e}")
            
            try:
                gb = GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=6,
                    random_state=42
                )
                models.append(('gb', gb))
                self.logger.debug("GradientBoosting model created")
            except Exception as e:
                self.logger.warning(f"Failed to create GradientBoosting: {e}")
            
            try:
                svm = SVC(
                    kernel='rbf',
                    probability=True,
                    random_state=42
                )
                models.append(('svm', svm))
                self.logger.debug("SVM model created")
            except Exception as e:
                self.logger.warning(f"Failed to create SVM: {e}")
            
            try:
                mlp = MLPClassifier(
                    hidden_layer_sizes=(100, 50),
                    max_iter=500,
                    random_state=42
                )
                models.append(('mlp', mlp))
                self.logger.debug("MLP model created")
            except Exception as e:
                self.logger.warning(f"Failed to create MLP: {e}")
            
            # Create ensemble if we have models
            if models:
                try:
                    self.models = VotingClassifier(
                        estimators=models,
                        voting='soft'
                    )
                    self.logger.info(f"Ensemble model created with {len(models)} base models")
                except Exception as e:
                    self.logger.error(f"Failed to create ensemble: {e}")
                    # Fallback to first available model
                    if models:
                        self.models = models[0][1]
                        self.logger.info(f"Using fallback model: {models[0][0]}")
            
            # Create scaler
            try:
                self.scaler = StandardScaler()
                self.logger.debug("StandardScaler created")
            except Exception as e:
                self.logger.warning(f"Failed to create scaler: {e}")
            
            # Create anomaly detector with version compatibility
            try:
                # Use different parameters based on sklearn version
                if SKLEARN_VERSION and SKLEARN_VERSION >= '0.22':
                    self.anomaly_detector = IsolationForest(
                        contamination=0.1,
                        random_state=42,
                        n_estimators=100
                    )
                else:
                    # Older version compatibility
                    self.anomaly_detector = IsolationForest(
                        contamination=0.1,
                        random_state=42,
                        n_estimators=100,
                        behaviour='new'  # For older versions
                    )
                self.logger.debug("IsolationForest anomaly detector created")
            except Exception as e:
                self.logger.warning(f"Failed to create anomaly detector: {e}")
                self.anomaly_detector = None
            
            # Create neural network if TensorFlow is available
            if HAS_TENSORFLOW:
                try:
                    self.neural_network = self._create_neural_network()
                    self.logger.debug("Neural network created")
                except Exception as e:
                    self.logger.warning(f"Failed to create neural network: {e}")
                    self.neural_network = None
            
        except Exception as e:
            self.logger.error(f"Model creation failed: {e}")
            raise

    def _create_neural_network(self):
        """Create neural network model"""
        if not HAS_TENSORFLOW:
            return None
        
        try:
            model = keras.Sequential([
                keras.layers.Dense(512, activation='relu', input_shape=(self.feature_size,)),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(256, activation='relu'),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(128, activation='relu'),
                keras.layers.Dropout(0.2),
                keras.layers.Dense(64, activation='relu'),
                keras.layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            return model
            
        except Exception as e:
            self.logger.error(f"Neural network creation failed: {e}")
            return None

    def _train_with_sample_data(self):
        """Train models with synthetic sample data"""
        try:
            self.logger.info("Training models with sample data...")
            
            # Generate synthetic training data
            X_train, y_train = self._generate_synthetic_data(1000)
            X_test, y_test = self._generate_synthetic_data(200)
            
            if self.scaler:
                X_train_scaled = self.scaler.fit_transform(X_train)
                X_test_scaled = self.scaler.transform(X_test)
            else:
                X_train_scaled = X_train
                X_test_scaled = X_test
            
            # Train ensemble model
            if self.models:
                try:
                    self.models.fit(X_train_scaled, y_train)
                    
                    # Evaluate ensemble
                    y_pred = self.models.predict(X_test_scaled)
                    accuracy = accuracy_score(y_test, y_pred)
                    self.model_stats['ensemble_accuracy'] = accuracy
                    
                    self.logger.info(f"Ensemble model trained - Accuracy: {accuracy:.3f}")
                    
                except Exception as e:
                    self.logger.error(f"Ensemble training failed: {e}")
            
            # Train anomaly detector
            if self.anomaly_detector:
                try:
                    # Train only on benign samples for anomaly detection
                    benign_samples = X_train_scaled[y_train == 0]
                    if len(benign_samples) > 0:
                        self.anomaly_detector.fit(benign_samples)
                        
                        # Test anomaly detection
                        anomaly_pred = self.anomaly_detector.predict(X_test_scaled)
                        # Convert to binary (1 for normal, -1 for anomaly)
                        anomaly_binary = (anomaly_pred == 1).astype(int)
                        # Invert for our labels (0 for benign, 1 for malicious)
                        anomaly_binary = 1 - anomaly_binary
                        
                        anomaly_accuracy = accuracy_score(y_test, anomaly_binary)
                        self.model_stats['anomaly_detector_accuracy'] = anomaly_accuracy
                        
                        self.logger.info(f"Anomaly detector trained - Accuracy: {anomaly_accuracy:.3f}")
                    
                except Exception as e:
                    self.logger.error(f"Anomaly detector training failed: {e}")
            
            # Train neural network
            if self.neural_network:
                try:
                    history = self.neural_network.fit(
                        X_train_scaled, y_train,
                        epochs=50,
                        batch_size=32,
                        validation_data=(X_test_scaled, y_test),
                        verbose=0
                    )
                    
                    # Evaluate neural network
                    _, nn_accuracy = self.neural_network.evaluate(X_test_scaled, y_test, verbose=0)
                    self.model_stats['neural_network_accuracy'] = nn_accuracy
                    
                    self.logger.info(f"Neural network trained - Accuracy: {nn_accuracy:.3f}")
                    
                except Exception as e:
                    self.logger.error(f"Neural network training failed: {e}")
            
            # Update training timestamp
            self.model_stats['last_training'] = time.time()
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise

    def _generate_synthetic_data(self, n_samples: int) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data"""
        if not HAS_NUMPY:
            raise AntivirusError("NumPy not available for data generation")
        
        try:
            # Generate features
            X = np.random.rand(n_samples, self.feature_size)
            
            # Generate labels (50% benign, 50% malicious)
            y = np.random.randint(0, 2, n_samples)
            
            # Add some patterns to make the data more realistic
            for i in range(n_samples):
                if y[i] == 1:  # Malicious
                    # Malicious files tend to have higher entropy, suspicious strings
                    X[i, :10] = np.random.rand(10) * 0.5 + 0.5  # Higher values
                    X[i, 10:20] = np.random.rand(10) * 0.3 + 0.7  # Even higher
                else:  # Benign
                    # Benign files have more normal patterns
                    X[i, :10] = np.random.rand(10) * 0.6  # Lower values
                    X[i, 10:20] = np.random.rand(10) * 0.4  # Lower values
            
            return X, y
            
        except Exception as e:
            self.logger.error(f"Synthetic data generation failed: {e}")
            raise

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict malware probability using ensemble models"""
        try:
            if not self.initialized:
                return {
                    'prediction': 'unknown',
                    'probability': 0.0,
                    'confidence': 0.0,
                    'error': 'ML detector not initialized'
                }
            
            if not HAS_NUMPY or features is None:
                return {
                    'prediction': 'unknown',
                    'probability': 0.0,
                    'confidence': 0.0,
                    'error': 'Invalid features or NumPy not available'
                }
            
            # Ensure features are in the right format
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Scale features if scaler is available
            if self.scaler:
                try:
                    features_scaled = self.scaler.transform(features)
                except Exception as e:
                    self.logger.warning(f"Feature scaling failed: {e}")
                    features_scaled = features
            else:
                features_scaled = features
            
            predictions = []
            probabilities = []
            
            # Ensemble model prediction
            if self.models:
                try:
                    if hasattr(self.models, 'predict_proba'):
                        ensemble_prob = self.models.predict_proba(features_scaled)[0]
                        if len(ensemble_prob) > 1:
                            prob = ensemble_prob[1]  # Probability of malicious
                        else:
                            prob = ensemble_prob[0]
                    else:
                        pred = self.models.predict(features_scaled)[0]
                        prob = float(pred)
                    
                    predictions.append('malicious' if prob > 0.5 else 'benign')
                    probabilities.append(prob)
                    
                except Exception as e:
                    self.logger.warning(f"Ensemble prediction failed: {e}")
            
            # Anomaly detector prediction
            if self.anomaly_detector:
                try:
                    anomaly_pred = self.anomaly_detector.predict(features_scaled)[0]
                    # IsolationForest returns -1 for anomalies, 1 for normal
                    anomaly_prob = 0.8 if anomaly_pred == -1 else 0.2
                    
                    predictions.append('malicious' if anomaly_pred == -1 else 'benign')
                    probabilities.append(anomaly_prob)
                    
                except Exception as e:
                    self.logger.warning(f"Anomaly detection failed: {e}")
            
            # Neural network prediction
            if self.neural_network:
                try:
                    nn_prob = self.neural_network.predict(features_scaled, verbose=0)[0][0]
                    predictions.append('malicious' if nn_prob > 0.5 else 'benign')
                    probabilities.append(float(nn_prob))
                    
                except Exception as e:
                    self.logger.warning(f"Neural network prediction failed: {e}")
            
            # Combine predictions
            if probabilities:
                avg_probability = np.mean(probabilities)
                final_prediction = 'malicious' if avg_probability > 0.5 else 'benign'
                confidence = abs(avg_probability - 0.5) * 2  # Scale to 0-1
                
                # Update statistics
                with self.model_lock:
                    self.model_stats['predictions_made'] += 1
                
                return {
                    'prediction': final_prediction,
                    'probability': float(avg_probability),
                    'confidence': float(confidence),
                    'models_used': len(probabilities),
                    'individual_predictions': predictions,
                    'individual_probabilities': [float(p) for p in probabilities]
                }
            else:
                return {
                    'prediction': 'unknown',
                    'probability': 0.0,
                    'confidence': 0.0,
                    'error': 'No models available for prediction'
                }
                
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            return {
                'prediction': 'error',
                'probability': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }

    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """Extract features from a file for ML analysis"""
        try:
            if not HAS_NUMPY:
                self.logger.warning("NumPy not available for feature extraction")
                return None
            
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            features = np.zeros(self.feature_size)
            
            # Basic file features
            try:
                stat = file_path.stat()
                features[0] = min(stat.st_size / (1024 * 1024), 100)  # Size in MB, capped at 100
                features[1] = stat.st_mtime % 1000000  # Modification time (normalized)
                features[2] = len(file_path.name)  # Filename length
            except Exception as e:
                self.logger.debug(f"Failed to get basic file features: {e}")
            
            # Extension-based features
            try:
                features[3:13] = self._extract_extension_features(file_path)
            except Exception as e:
                self.logger.debug(f"Failed to extract extension features: {e}")
            
            # Content-based features
            try:
                content_features = self._extract_content_features(file_path)
                if content_features is not None:
                    features[13:] = content_features[:self.feature_size-13]
            except Exception as e:
                self.logger.debug(f"Failed to extract content features: {e}")
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed for {file_path}: {e}")
            return None

    def _extract_extension_features(self, file_path: Path) -> np.ndarray:
        """Extract extension-based features"""
        features = np.zeros(10)
        
        extension = file_path.suffix.lower()
        
        # Common executable extensions
        executable_exts = {'.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif'}
        features[0] = 1.0 if extension in executable_exts else 0.0
        
        # Script extensions
        script_exts = {'.js', '.vbs', '.ps1', '.py', '.pl', '.sh'}
        features[1] = 1.0 if extension in script_exts else 0.0
        
        # Archive extensions
        archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz'}
        features[2] = 1.0 if extension in archive_exts else 0.0
        
        # Document extensions
        doc_exts = {'.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'}
        features[3] = 1.0 if extension in doc_exts else 0.0
        
        # Image extensions
        img_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
        features[4] = 1.0 if extension in img_exts else 0.0
        
        return features

    def _extract_content_features(self, file_path: Path) -> Optional[np.ndarray]:
        """Extract content-based features"""
        try:
            # Read first 8KB of file for analysis
            with open(file_path, 'rb') as f:
                content = f.read(8192)
            
            if not content:
                return None
            
            features = np.zeros(self.feature_size - 13)
            
            # Entropy
            features[0] = self._calculate_entropy(content)
            
            # Byte frequency analysis
            byte_counts = np.bincount(np.frombuffer(content, dtype=np.uint8), minlength=256)
            byte_freq = byte_counts / len(content)
            features[1:257] = byte_freq  # First 256 features for byte frequencies
            
            return features
            
        except Exception as e:
            self.logger.debug(f"Content feature extraction failed: {e}")
            return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        try:
            # Count byte frequencies
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
            probabilities = byte_counts[byte_counts > 0] / len(data)
            
            # Calculate entropy
            entropy = -np.sum(probabilities * np.log2(probabilities))
            return entropy / 8.0  # Normalize to 0-1 range
            
        except Exception:
            return 0.0

    def _save_models(self):
        """Save trained models to disk"""
        try:
            models_file = self.models_dir / "ensemble_models.pkl"
            scaler_file = self.models_dir / "scaler.pkl"
            stats_file = self.models_dir / "model_stats.json"
            
            # Save ensemble models
            if self.models:
                joblib.dump(self.models, models_file)
                self.logger.debug("Ensemble models saved")
            
            # Save scaler
            if self.scaler:
                joblib.dump(self.scaler, scaler_file)
                self.logger.debug("Scaler saved")
            
            # Save anomaly detector
            if self.anomaly_detector:
                anomaly_file = self.models_dir / "anomaly_detector.pkl"
                joblib.dump(self.anomaly_detector, anomaly_file)
                self.logger.debug("Anomaly detector saved")
            
            # Save neural network
            if self.neural_network:
                nn_file = self.models_dir / "neural_network.h5"
                self.neural_network.save(nn_file)
                self.logger.debug("Neural network saved")
            
            # Save statistics
            import json
            with open(stats_file, 'w') as f:
                json.dump(self.model_stats, f, indent=2)
            
            self.logger.info("All models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")

    def _load_models(self) -> bool:
        """Load trained models from disk"""
        try:
            models_file = self.models_dir / "ensemble_models.pkl"
            scaler_file = self.models_dir / "scaler.pkl"
            anomaly_file = self.models_dir / "anomaly_detector.pkl"
            nn_file = self.models_dir / "neural_network.h5"
            stats_file = self.models_dir / "model_stats.json"
            
            # Load ensemble models
            if models_file.exists():
                self.models = joblib.load(models_file)
                self.logger.debug("Ensemble models loaded")
            
            # Load scaler
            if scaler_file.exists():
                self.scaler = joblib.load(scaler_file)
                self.logger.debug("Scaler loaded")
            
            # Load anomaly detector
            if anomaly_file.exists():
                self.anomaly_detector = joblib.load(anomaly_file)
                self.logger.debug("Anomaly detector loaded")
            
            # Load neural network
            if nn_file.exists() and HAS_TENSORFLOW:
                self.neural_network = keras.models.load_model(nn_file)
                self.logger.debug("Neural network loaded")
            
            # Load statistics
            if stats_file.exists():
                import json
                with open(stats_file, 'r') as f:
                    self.model_stats.update(json.load(f))
            
            # Check if we have at least one model
            has_models = any([
                self.models is not None,
                self.anomaly_detector is not None,
                self.neural_network is not None
            ])
            
            if has_models:
                self.logger.info("Models loaded successfully")
                return True
            else:
                self.logger.info("No existing models found")
                return False
                
        except Exception as e:
            self.logger.warning(f"Failed to load models: {e}")
            return False

    def is_initialized(self) -> bool:
        """Check if ML detector is properly initialized"""
        return self.initialized

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'initialized': self.initialized,
            'has_ensemble': self.models is not None,
            'has_anomaly_detector': self.anomaly_detector is not None,
            'has_neural_network': self.neural_network is not None,
            'has_scaler': self.scaler is not None,
            'sklearn_available': HAS_SKLEARN,
            'tensorflow_available': HAS_TENSORFLOW,
            'numpy_available': HAS_NUMPY,
            'sklearn_version': SKLEARN_VERSION,
            'feature_size': self.feature_size,
            'models_directory': str(self.models_dir)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get model statistics"""
        return {
            **self.get_model_info(),
            **self.model_stats
        }

def main():
    """Test ML detector functionality"""
    try:
        detector = EnsembleMLDetector()
        
        if detector.initialize():
            print("✓ ML Detector initialized successfully")
            
            # Test feature extraction
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(b"test content for ML analysis")
                tmp_path = tmp.name
            
            features = detector.extract_features(tmp_path)
            if features is not None:
                print("✓ Feature extraction successful")
                
                # Test prediction
                result = detector.predict(features)
                print(f"✓ Prediction result: {result}")
            else:
                print("✗ Feature extraction failed")
            
            # Cleanup
            os.unlink(tmp_path)
            
            # Print statistics
            stats = detector.get_statistics()
            print(f"✓ Model statistics: {stats}")
            
        else:
            print("✗ ML Detector initialization failed")
            
    except Exception as e:
        print(f"✗ ML Detector test failed: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())