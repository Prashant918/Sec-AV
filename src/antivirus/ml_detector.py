import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report
import tensorflow as tf
from tensorflow import keras
import pickle
import threading
from typing import Tuple, Optional, Dict, Any, List
from .logger import SecureLogger
from .config import secure_config

class EnsembleMLDetector:
    """Advanced ensemble ML detector with multiple algorithms"""
    
    def __init__(self):
        self.logger = SecureLogger("MLDetector")
        self.models = {}
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_lock = threading.Lock()
        
        # Model paths
        self.model_dir = "models"
        self.ensemble_model_path = os.path.join(self.model_dir, "ensemble_model.pkl")
        self.scaler_path = os.path.join(self.model_dir, "scaler.pkl")
        self.nn_model_path = os.path.join(self.model_dir, "neural_network.h5")
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
    
    def initialize(self) -> bool:
        """Initialize ML models"""
        try:
            self.logger.info("Initializing ML detector...")
            
            # Try to load existing models
            if self._load_models():
                self.logger.info("Loaded existing ML models")
                return True
            
            # Create and train new models if none exist
            self.logger.info("Creating new ML models...")
            self._create_models()
            
            # Load sample data and train (in production, use real malware dataset)
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
        """Create ensemble of ML models"""
        # Random Forest
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Gradient Boosting
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        
        # Support Vector Machine
        svm_model = SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
        
        # Multi-layer Perceptron
        mlp_model = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            max_iter=500,
            random_state=42
        )
        
        # Create voting ensemble
        self.ensemble_model = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('gb', gb_model),
                ('svm', svm_model),
                ('mlp', mlp_model)
            ],
            voting='soft'
        )
        
        # Create deep neural network
        self._create_neural_network()
    
    def _create_neural_network(self):
        """Create deep neural network model"""
        self.nn_model = keras.Sequential([
            keras.layers.Dense(512, activation='relu', input_shape=(259,)),  # Adjust based on features
            keras.layers.Dropout(0.3),
            keras.layers.Dense(256, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.nn_model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
    
    def _train_with_sample_data(self) -> bool:
        """Train models with sample data (replace with real dataset in production)"""
        try:
            # Generate synthetic training data (replace with real malware dataset)
            X_train, y_train = self._generate_synthetic_data(10000)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train ensemble model
            self.ensemble_model.fit(X_train_scaled, y_train)
            
            # Train neural network
            self.nn_model.fit(
                X_train_scaled, y_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Evaluate models
            ensemble_score = cross_val_score(self.ensemble_model, X_train_scaled, y_train, cv=5)
            self.logger.info(f"Ensemble model CV score: {ensemble_score.mean():.3f} (+/- {ensemble_score.std() * 2:.3f})")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            return False
    
    def _generate_synthetic_data(self, n_samples: int) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data (replace with real dataset)"""
        np.random.seed(42)
        
        # Generate features (259 features to match expected input)
        X = np.random.rand(n_samples, 259)
        
        # Generate labels (50% malicious, 50% benign)
        y = np.random.randint(0, 2, n_samples)
        
        # Add some patterns to make it more realistic
        for i in range(n_samples):
            if y[i] == 1:  # Malicious
                # High entropy indicator
                X[i, 1] = np.random.uniform(6.5, 8.0)
                # Suspicious byte patterns
                X[i, 2:10] = np.random.uniform(0.8, 1.0, 8)
            else:  # Benign
                # Normal entropy
                X[i, 1] = np.random.uniform(3.0, 6.5)
                # Normal byte patterns
                X[i, 2:10] = np.random.uniform(0.0, 0.5, 8)
        
        return X, y
    
    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        """Predict if file is malicious using ensemble approach"""
        try:
            with self.model_lock:
                if not self.is_trained:
                    return 0, 0.0
                
                # Ensure features have correct shape
                if features.shape[1] != 259:
                    self.logger.warning(f"Feature dimension mismatch: expected 259, got {features.shape[1]}")
                    return 0, 0.0
                
                # Scale features
                features_scaled = self.scaler.transform(features)
                
                # Get predictions from ensemble model
                ensemble_pred = self.ensemble_model.predict(features_scaled)[0]
                ensemble_proba = self.ensemble_model.predict_proba(features_scaled)[0]
                
                # Get prediction from neural network
                nn_proba = self.nn_model.predict(features_scaled, verbose=0)[0][0]
                nn_pred = 1 if nn_proba > 0.5 else 0
                
                # Combine predictions (weighted average)
                final_proba = (ensemble_proba[1] * 0.7) + (nn_proba * 0.3)
                final_pred = 1 if final_proba > 0.5 else 0
                
                return final_pred, float(final_proba)
                
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            return 0, 0.0
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save ensemble model
            joblib.dump(self.ensemble_model, self.ensemble_model_path)
            
            # Save scaler
            joblib.dump(self.scaler, self.scaler_path)
            
            # Save neural network
            self.nn_model.save(self.nn_model_path)
            
            self.logger.info("ML models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def _load_models(self) -> bool:
        """Load trained models from disk"""
        try:
            if not all(os.path.exists(path) for path in [
                self.ensemble_model_path, self.scaler_path, self.nn_model_path
            ]):
                return False
            
            # Load ensemble model
            self.ensemble_model = joblib.load(self.ensemble_model_path)
            
            # Load scaler
            self.scaler = joblib.load(self.scaler_path)
            
            # Load neural network
            self.nn_model = keras.models.load_model(self.nn_model_path)
            
            self.is_trained = True
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")
            return False
    
    def update_models(self, X_new: np.ndarray, y_new: np.ndarray) -> bool:
        """Update models with new training data"""
        try:
            with self.model_lock:
                if not self.is_trained:
                    return False
                
                # Scale new features
                X_new_scaled = self.scaler.transform(X_new)
                
                # Partial fit for models that support it
                # Note: Not all sklearn models support partial_fit
                # In production, consider using online learning algorithms
                
                # Retrain neural network with new data
                self.nn_model.fit(
                    X_new_scaled, y_new,
                    epochs=10,
                    batch_size=32,
                    verbose=0
                )
                
                # Save updated models
                self._save_models()
                
                self.logger.info(f"Models updated with {len(X_new)} new samples")
                return True
                
        except Exception as e:
            self.logger.error(f"Model update failed: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if ML detector is initialized"""
        return self.is_trained
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            "ensemble_models": ["RandomForest", "GradientBoosting", "SVM", "MLP"],
            "neural_network": "Deep NN (5 layers)",
            "feature_count": 259,
            "is_trained": self.is_trained,
            "model_files_exist": all(os.path.exists(path) for path in [
                self.ensemble_model_path, self.scaler_path, self.nn_model_path
            ])
        }