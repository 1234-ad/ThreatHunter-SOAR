"""
Advanced ML Threat Classification Model
Uses ensemble methods and deep learning for threat detection and classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import json
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract features from network and system logs for ML models"""
    
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False
    
    def extract_network_features(self, log_data: Dict) -> Dict:
        """Extract network-based features"""
        features = {}
        
        # Basic network features
        features['src_port'] = log_data.get('source_port', 0)
        features['dst_port'] = log_data.get('destination_port', 0)
        features['protocol'] = self._encode_protocol(log_data.get('protocol', 'unknown'))
        features['packet_size'] = log_data.get('packet_size', 0)
        features['duration'] = log_data.get('duration', 0)
        
        # IP-based features
        src_ip = log_data.get('source_ip', '0.0.0.0')
        dst_ip = log_data.get('destination_ip', '0.0.0.0')
        
        features['src_ip_private'] = self._is_private_ip(src_ip)
        features['dst_ip_private'] = self._is_private_ip(dst_ip)
        features['same_subnet'] = self._same_subnet(src_ip, dst_ip)
        
        # Port analysis
        features['src_port_suspicious'] = self._is_suspicious_port(features['src_port'])
        features['dst_port_suspicious'] = self._is_suspicious_port(features['dst_port'])
        features['port_ratio'] = features['src_port'] / max(features['dst_port'], 1)
        
        # Traffic patterns
        features['bytes_in'] = log_data.get('bytes_in', 0)
        features['bytes_out'] = log_data.get('bytes_out', 0)
        features['packets_in'] = log_data.get('packets_in', 0)
        features['packets_out'] = log_data.get('packets_out', 0)
        
        # Calculate ratios
        total_bytes = features['bytes_in'] + features['bytes_out']
        total_packets = features['packets_in'] + features['packets_out']
        
        features['byte_ratio'] = features['bytes_out'] / max(total_bytes, 1)
        features['packet_ratio'] = features['packets_out'] / max(total_packets, 1)
        features['avg_packet_size'] = total_bytes / max(total_packets, 1)
        
        return features
    
    def extract_process_features(self, log_data: Dict) -> Dict:
        """Extract process-based features"""
        features = {}
        
        # Process information
        process_name = log_data.get('process_name', '')
        command_line = log_data.get('command_line', '')
        parent_process = log_data.get('parent_process', '')
        
        features['process_name_len'] = len(process_name)
        features['cmdline_len'] = len(command_line)
        features['parent_process_len'] = len(parent_process)
        
        # Suspicious process patterns
        features['powershell_detected'] = 'powershell' in process_name.lower()
        features['cmd_detected'] = 'cmd.exe' in process_name.lower()
        features['encoded_command'] = '-enc' in command_line.lower() or '-e ' in command_line.lower()
        features['bypass_execution_policy'] = 'bypass' in command_line.lower()
        features['hidden_window'] = 'hidden' in command_line.lower()
        
        # Command line analysis
        features['cmdline_entropy'] = self._calculate_entropy(command_line)
        features['cmdline_base64_ratio'] = self._base64_ratio(command_line)
        features['cmdline_special_chars'] = self._special_char_ratio(command_line)
        
        # Process behavior
        features['process_id'] = log_data.get('process_id', 0)
        features['parent_process_id'] = log_data.get('parent_process_id', 0)
        features['user_name'] = log_data.get('user_name', '')
        features['is_system_user'] = features['user_name'].lower() in ['system', 'local service', 'network service']
        
        return features
    
    def extract_file_features(self, log_data: Dict) -> Dict:
        """Extract file-based features"""
        features = {}
        
        file_path = log_data.get('file_path', '')
        file_name = log_data.get('file_name', '')
        file_extension = log_data.get('file_extension', '')
        
        # File path analysis
        features['file_path_len'] = len(file_path)
        features['file_name_len'] = len(file_name)
        features['path_depth'] = file_path.count('\\\\') + file_path.count('/')
        
        # Suspicious locations
        suspicious_paths = [
            'temp', 'tmp', 'appdata', 'programdata', 'users\\\\public',
            'windows\\\\system32', 'windows\\\\syswow64'
        ]
        features['suspicious_location'] = any(path in file_path.lower() for path in suspicious_paths)
        
        # File extension analysis
        executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        features['is_executable'] = file_extension.lower() in executable_extensions
        
        # File attributes
        features['file_size'] = log_data.get('file_size', 0)
        features['file_created'] = log_data.get('file_created', 0)
        features['file_modified'] = log_data.get('file_modified', 0)
        features['file_accessed'] = log_data.get('file_accessed', 0)
        
        # Hash information
        features['has_md5'] = bool(log_data.get('md5_hash'))
        features['has_sha1'] = bool(log_data.get('sha1_hash'))
        features['has_sha256'] = bool(log_data.get('sha256_hash'))
        
        return features
    
    def extract_text_features(self, log_data: Dict) -> np.ndarray:
        """Extract text-based features using TF-IDF"""
        # Combine relevant text fields
        text_fields = []
        
        for field in ['command_line', 'process_name', 'file_path', 'user_agent', 'url']:
            if field in log_data:
                text_fields.append(str(log_data[field]))
        
        combined_text = ' '.join(text_fields)
        
        if self.is_fitted:
            return self.tfidf_vectorizer.transform([combined_text]).toarray()[0]
        else:
            # During training, we'll fit the vectorizer
            return combined_text
    
    def _encode_protocol(self, protocol: str) -> int:
        """Encode protocol to numeric value"""
        protocol_map = {
            'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5,
            'dns': 6, 'ftp': 7, 'ssh': 8, 'telnet': 9, 'smtp': 10
        }
        return protocol_map.get(protocol.lower(), 0)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(x) for x in ip.split('.')]
            if parts[0] == 10:
                return True
            elif parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            elif parts[0] == 192 and parts[1] == 168:
                return True
            return False
        except:
            return False
    
    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if IPs are in same subnet (simple /24 check)"""
        try:
            parts1 = ip1.split('.')[:3]
            parts2 = ip2.split('.')[:3]
            return parts1 == parts2
        except:
            return False
    
    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly used by malware"""
        suspicious_ports = [
            4444, 8080, 9999, 1337, 31337, 6666, 7777, 8888,
            1234, 12345, 54321, 9090, 8000, 3389, 5900
        ]
        return port in suspicious_ports
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _base64_ratio(self, text: str) -> float:
        """Calculate ratio of base64-like characters"""
        if not text:
            return 0.0
        
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        base64_count = sum(1 for char in text if char in base64_chars)
        
        return base64_count / len(text)
    
    def _special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters"""
        if not text:
            return 0.0
        
        special_chars = set('!@#$%^&*()[]{}|\\:";\'<>?,./`~')
        special_count = sum(1 for char in text if char in special_chars)
        
        return special_count / len(text)

class ThreatClassifier:
    """Advanced ML-based threat classifier"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.models = {}
        self.ensemble_weights = {}
        self.threat_types = [
            'benign', 'malware', 'network_intrusion', 'data_exfiltration',
            'privilege_escalation', 'lateral_movement', 'persistence'
        ]
        self.is_trained = False
    
    def initialize_models(self):
        """Initialize ML models"""
        # Random Forest for robust performance
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        # Gradient Boosting for high accuracy
        self.models['gradient_boosting'] = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            random_state=42
        )
        
        # Neural Network for complex patterns
        self.models['neural_network'] = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=32,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        # Set ensemble weights (can be tuned based on validation performance)
        self.ensemble_weights = {
            'random_forest': 0.4,
            'gradient_boosting': 0.4,
            'neural_network': 0.2
        }
        
        logger.info("Initialized ML models for threat classification")
    
    def prepare_features(self, log_data_list: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """Prepare features from log data"""
        feature_vectors = []
        text_data = []
        
        for log_data in log_data_list:
            # Extract different types of features
            network_features = self.feature_extractor.extract_network_features(log_data)
            process_features = self.feature_extractor.extract_process_features(log_data)
            file_features = self.feature_extractor.extract_file_features(log_data)
            
            # Combine all features
            combined_features = {**network_features, **process_features, **file_features}
            
            # Convert to list maintaining consistent order
            feature_names = sorted(combined_features.keys())
            feature_vector = [combined_features[name] for name in feature_names]
            
            feature_vectors.append(feature_vector)
            
            # Extract text for TF-IDF
            text_data.append(self.feature_extractor.extract_text_features(log_data))
        
        # Convert to numpy array
        X_structured = np.array(feature_vectors)
        
        # Handle text features
        if not self.feature_extractor.is_fitted:
            # Fit TF-IDF during training
            X_text = self.feature_extractor.tfidf_vectorizer.fit_transform(text_data).toarray()
            self.feature_extractor.is_fitted = True
        else:
            # Transform during prediction
            X_text = self.feature_extractor.tfidf_vectorizer.transform(text_data).toarray()
        
        # Combine structured and text features
        X_combined = np.hstack([X_structured, X_text])
        
        # Scale features
        if not hasattr(self.feature_extractor.scaler, 'scale_'):
            X_combined = self.feature_extractor.scaler.fit_transform(X_combined)
        else:
            X_combined = self.feature_extractor.scaler.transform(X_combined)
        
        return X_combined, feature_names
    
    def train(self, training_data: List[Dict], labels: List[str]) -> Dict:
        """Train the threat classification models"""
        logger.info(f"Training threat classifier with {len(training_data)} samples")
        
        try:
            # Initialize models
            self.initialize_models()
            
            # Prepare features
            X, feature_names = self.prepare_features(training_data)
            
            # Encode labels
            label_encoder = LabelEncoder()
            y = label_encoder.fit_transform(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train each model
            model_scores = {}
            
            for model_name, model in self.models.items():
                logger.info(f"Training {model_name}...")
                
                # Train model
                model.fit(X_train, y_train)
                
                # Evaluate model
                train_score = model.score(X_train, y_train)
                test_score = model.score(X_test, y_test)
                
                # Cross-validation score
                cv_scores = cross_val_score(model, X_train, y_train, cv=5)
                cv_mean = cv_scores.mean()
                cv_std = cv_scores.std()
                
                model_scores[model_name] = {
                    'train_score': train_score,
                    'test_score': test_score,
                    'cv_mean': cv_mean,
                    'cv_std': cv_std
                }
                
                logger.info(f"{model_name} - Train: {train_score:.3f}, Test: {test_score:.3f}, CV: {cv_mean:.3f}±{cv_std:.3f}")
            
            # Generate detailed evaluation
            evaluation_results = self._evaluate_models(X_test, y_test, label_encoder)
            
            self.is_trained = True
            
            return {
                'model_scores': model_scores,
                'evaluation_results': evaluation_results,
                'feature_count': X.shape[1],
                'training_samples': len(training_data),
                'classes': list(label_encoder.classes_)
            }
        
        except Exception as e:
            logger.error(f"Training failed: {str(e)}")
            raise
    
    def predict(self, log_data: Dict) -> Dict:
        """Predict threat classification for single log entry"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        try:
            # Prepare features
            X, _ = self.prepare_features([log_data])
            
            # Get predictions from each model
            predictions = {}
            probabilities = {}
            
            for model_name, model in self.models.items():
                pred = model.predict(X)[0]
                pred_proba = model.predict_proba(X)[0]
                
                predictions[model_name] = pred
                probabilities[model_name] = pred_proba
            
            # Ensemble prediction (weighted voting)
            ensemble_proba = np.zeros(len(self.threat_types))
            
            for model_name, weight in self.ensemble_weights.items():
                ensemble_proba += weight * probabilities[model_name]
            
            # Final prediction
            final_prediction = np.argmax(ensemble_proba)
            final_confidence = ensemble_proba[final_prediction]
            
            # Map to threat type
            threat_type = self.threat_types[final_prediction]
            
            # Calculate threat score (0-100)
            threat_score = final_confidence * 100
            
            # Determine severity based on threat type and confidence
            severity = self._determine_severity(threat_type, final_confidence)
            
            return {
                'threat_type': threat_type,
                'confidence': float(final_confidence),
                'threat_score': float(threat_score),
                'severity': severity,
                'individual_predictions': {
                    model_name: {
                        'prediction': self.threat_types[pred],
                        'confidence': float(max(proba))
                    }
                    for model_name, (pred, proba) in zip(predictions.items(), probabilities.values())
                },
                'class_probabilities': {
                    threat_type: float(prob)
                    for threat_type, prob in zip(self.threat_types, ensemble_proba)
                }
            }
        
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            raise
    
    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray, label_encoder: LabelEncoder) -> Dict:
        """Evaluate trained models"""
        evaluation_results = {}
        
        for model_name, model in self.models.items():
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)
            
            # Classification report
            class_report = classification_report(
                y_test, y_pred,
                target_names=label_encoder.classes_,
                output_dict=True
            )
            
            # Confusion matrix
            conf_matrix = confusion_matrix(y_test, y_pred)
            
            # ROC AUC (for multiclass)
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')
            except:
                roc_auc = None
            
            evaluation_results[model_name] = {
                'classification_report': class_report,
                'confusion_matrix': conf_matrix.tolist(),
                'roc_auc': roc_auc
            }
        
        return evaluation_results
    
    def _determine_severity(self, threat_type: str, confidence: float) -> str:
        """Determine severity based on threat type and confidence"""
        if threat_type == 'benign':
            return 'low'
        
        # High-risk threat types
        high_risk_threats = ['malware', 'data_exfiltration', 'privilege_escalation']
        medium_risk_threats = ['network_intrusion', 'lateral_movement', 'persistence']
        
        if threat_type in high_risk_threats:
            if confidence > 0.8:
                return 'critical'
            elif confidence > 0.6:
                return 'high'
            else:
                return 'medium'
        
        elif threat_type in medium_risk_threats:
            if confidence > 0.8:
                return 'high'
            elif confidence > 0.6:
                return 'medium'
            else:
                return 'low'
        
        return 'low'
    
    def save_model(self, filepath: str):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'models': self.models,
            'feature_extractor': self.feature_extractor,
            'ensemble_weights': self.ensemble_weights,
            'threat_types': self.threat_types,
            'is_trained': self.is_trained,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from file"""
        try:
            model_data = joblib.load(filepath)
            
            self.models = model_data['models']
            self.feature_extractor = model_data['feature_extractor']
            self.ensemble_weights = model_data['ensemble_weights']
            self.threat_types = model_data['threat_types']
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise

# Example usage and testing
if __name__ == "__main__":
    # Initialize classifier
    classifier = ThreatClassifier()
    
    # Generate sample training data (in production, use real data)
    sample_data = [
        {
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'source_port': 12345,
            'destination_port': 53,
            'protocol': 'udp',
            'bytes_in': 100,
            'bytes_out': 200,
            'process_name': 'chrome.exe',
            'command_line': 'chrome.exe --no-sandbox',
            'file_path': 'C:\\\\Program Files\\\\Google\\\\Chrome\\\\chrome.exe'
        },
        {
            'source_ip': '10.0.0.50',
            'destination_ip': '192.168.1.1',
            'source_port': 4444,
            'destination_port': 80,
            'protocol': 'tcp',
            'bytes_in': 1000,
            'bytes_out': 50000,
            'process_name': 'powershell.exe',
            'command_line': 'powershell.exe -enc SGVsbG8gV29ybGQ=',
            'file_path': 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
        }
    ]
    
    sample_labels = ['benign', 'malware']
    
    # Train model
    results = classifier.train(sample_data, sample_labels)
    print("Training Results:", json.dumps(results, indent=2, default=str))
    
    # Test prediction
    test_data = sample_data[1]  # Use malware sample
    prediction = classifier.predict(test_data)
    print("Prediction:", json.dumps(prediction, indent=2))