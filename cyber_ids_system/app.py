from flask import Flask, render_template, jsonify, request
import psutil
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os
import time
import random
import threading

# Import new modules
import database
from sniffer import PacketSniffer

app = Flask(__name__)

# Load trained model
try:
    model = joblib.load('models/fl_ids_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    feature_names = joblib.load('models/feature_names.pkl')
    
    # Load DL Models
    import tensorflow as tf
    cnn_model = tf.keras.models.load_model('models/cnn_ids_model.h5')
    lstm_model = tf.keras.models.load_model('models/lstm_ids_model.h5')
    scaler_dl = joblib.load('models/scaler_dl.pkl')
    
    print("✅ All Models (RF, CNN, LSTM) loaded successfully!")
except Exception as e:
    print(f"⚠️  Error loading models: {e}")
    model = None
    scaler = None
    feature_names = None
    cnn_model = None
    lstm_model = None
    scaler_dl = None

# Global variables
attack_detected = False
system_metrics_before = {'cpu': [], 'memory': [], 'network': []}
system_metrics_after = {'cpu': [], 'memory': [], 'network': []}

# Initialize Sniffer
packet_sniffer = PacketSniffer()

# Initialize Database
try:
    database.init_db()
except Exception as e:
    print(f"⚠️ Database Init Error: {e}")

def get_system_metrics():
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    network = psutil.net_io_counters()
    
    return {
        'cpu': cpu_percent,
        'memory': memory.percent,
        'disk': psutil.disk_usage('/').percent,
        'network_sent': network.bytes_sent,
        'network_recv': network.bytes_recv,
        'timestamp': datetime.now().isoformat()
    }

def simulate_network_traffic():
    # Fallback simulation if no real traffic
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'telnet', 'ssh', 'domain', 'private']
    flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH']
    
    is_malicious = random.random() < 0.15
    
    if is_malicious:
        traffic = {
            'duration': random.randint(100, 5000),
            'src_bytes': random.randint(10000, 1000000),
            'dst_bytes': random.randint(0, 1000),
            'wrong_fragment': random.randint(1, 3),
            'urgent': random.randint(0, 2),
            'hot': random.randint(5, 20),
            'num_failed_logins': random.randint(1, 5),
            'num_compromised': random.randint(1, 10),
            'num_root': random.randint(1, 5),
            'num_file_creations': random.randint(0, 3),
            'count': random.randint(50, 500),
            'srv_count': random.randint(1, 50),
        }
    else:
        traffic = {
            'duration': random.randint(0, 100),
            'src_bytes': random.randint(100, 10000),
            'dst_bytes': random.randint(100, 10000),
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': random.randint(0, 2),
            'num_failed_logins': 0,
            'num_compromised': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'count': random.randint(1, 10),
            'srv_count': random.randint(1, 10),
        }
    
    traffic['protocol_type'] = random.choice(protocols)
    traffic['service'] = random.choice(services)
    traffic['flag'] = random.choice(flags)
    traffic['src_ip'] = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    traffic['dst_ip'] = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
    traffic['timestamp'] = datetime.now().isoformat()
    
    # Fill missing keys with defaults to match model features
    defaults = {
        'land': 0, 'logged_in': 0, 'root_shell': 0, 'su_attempted': 0,
        'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': random.randint(1, 255), 'dst_host_srv_count': random.randint(1, 255),
        'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
    }
    traffic.update(defaults)
    
    return traffic, is_malicious

def predict_traffic(traffic_data):
    if model is None or scaler is None:
        return {'prediction': 'unknown', 'confidence': 0}
    
    try:
        # 1. Prepare Features for Random Forest
        features = []
        for fname in feature_names:
            if fname in traffic_data:
                val = traffic_data[fname]
                if isinstance(val, str):
                    val = hash(val) % 100
                features.append(val)
            else:
                features.append(0)
        
        features_array = np.array(features).reshape(1, -1)
        features_scaled = scaler.transform(features_array)
        
        # 2. Random Forest Prediction
        rf_prediction = model.predict(features_scaled)[0]
        rf_probs = model.predict_proba(features_scaled)[0]
        rf_confidence = float(max(rf_probs))
        
        # 3. Deep Learning Prediction (CNN & LSTM)
        # Reshape for DL (1, 1, features)
        if scaler_dl:
             dl_features_scaled = scaler_dl.transform(features_array)
             dl_input = dl_features_scaled.reshape((1, 1, dl_features_scaled.shape[1]))
             
             cnn_probs = cnn_model.predict(dl_input, verbose=0)[0]
             lstm_probs = lstm_model.predict(dl_input, verbose=0)[0]
             
             # Ensemble DL probabilities (Average)
             dl_probs = (cnn_probs + lstm_probs) / 2
             dl_confidence = float(max(dl_probs))
             dl_prediction = np.argmax(dl_probs)
        else:
             dl_confidence = 0
             dl_prediction = rf_prediction # Fallback
        
        # 4. RQA Analysis (Get metrics from traffic_data)
        rqa_det = traffic_data.get('rqa_det', 0)
        rqa_rr = traffic_data.get('rqa_rr', 0)
        
        # 5. Decision-Level Fusion Logic
        threat_types = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R', 'Unknown']
        
        # Map numeric predictions to labels
        rf_label = threat_types[min(rf_prediction, len(threat_types)-1)]
        dl_label = threat_types[min(dl_prediction, len(threat_types)-1)]
        
        is_malicious = False
        final_prediction = "Normal"
        fusion_score = 0
        threat_level = 'Low'
        
        # Logic:
        # If RQA DET > 90%, it's a high confidence anomaly (likely Bot/DDoS)
        if rqa_det > 90:
            is_malicious = True
            final_prediction = "Anomaly (RQA)"
            fusion_score = 0.95
            threat_level = 'Critical'
        
        # Else, trust the ML models
        elif rf_label != 'Normal' or dl_label != 'Normal':
            is_malicious = True
            # If both agree
            if rf_label == dl_label:
                final_prediction = rf_label
                fusion_score = (rf_confidence + dl_confidence) / 2
            else:
                # Trust the one with higher confidence
                if rf_confidence > dl_confidence:
                    final_prediction = rf_label
                    fusion_score = rf_confidence
                else:
                    final_prediction = dl_label
                    fusion_score = dl_confidence
            
            threat_level = 'High' if fusion_score > 0.8 else 'Medium'
            
        else:
            # All Normal
            is_malicious = False
            final_prediction = "Normal"
            fusion_score = (rf_confidence + dl_confidence) / 2
            threat_level = 'Low'

        return {
            'prediction': final_prediction,
            'is_malicious': is_malicious,
            'confidence': fusion_score,
            'threat_level': threat_level,
            'details': {
                'rf_label': rf_label,
                'dl_label': dl_label,
                'rqa_det': rqa_det
            }
        }
    except Exception as e:
        print(f"Prediction error: {e}")
        return {'prediction': 'error', 'confidence': 0, 'is_malicious': False}

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/database')
def view_database():
    logs = database.get_all_logs(limit=100)
    blocked_ips = database.get_blocked_ips_details()
    return render_template('database.html', logs=logs, blocked_ips=blocked_ips)

@app.route('/api/system-metrics')
def system_metrics():
    global attack_detected, system_metrics_before, system_metrics_after
    
    metrics = get_system_metrics()
    
    if attack_detected:
        system_metrics_after['cpu'].append(metrics['cpu'])
        system_metrics_after['memory'].append(metrics['memory'])
        system_metrics_after['network'].append(metrics['network_sent'])
        
        if len(system_metrics_after['cpu']) > 50:
            system_metrics_after['cpu'].pop(0)
            system_metrics_after['memory'].pop(0)
            system_metrics_after['network'].pop(0)
    else:
        system_metrics_before['cpu'].append(metrics['cpu'])
        system_metrics_before['memory'].append(metrics['memory'])
        system_metrics_before['network'].append(metrics['network_sent'])
        
        if len(system_metrics_before['cpu']) > 50:
            system_metrics_before['cpu'].pop(0)
            system_metrics_before['memory'].pop(0)
            system_metrics_before['network'].pop(0)
    
    return jsonify({
        'current': metrics,
        'before_attack': {
            'cpu': system_metrics_before['cpu'][-10:] if system_metrics_before['cpu'] else [],
            'memory': system_metrics_before['memory'][-10:] if system_metrics_before['memory'] else [],
            'network': system_metrics_before['network'][-10:] if system_metrics_before['network'] else []
        },
        'after_attack': {
            'cpu': system_metrics_after['cpu'][-10:] if system_metrics_after['cpu'] else [],
            'memory': system_metrics_after['memory'][-10:] if system_metrics_after['memory'] else [],
            'network': system_metrics_after['network'][-10:] if system_metrics_after['network'] else []
        },
        'attack_detected': attack_detected
    })

@app.route('/api/traffic-monitor')
def traffic_monitor():
    global attack_detected
    
    # 1. Try to get real packet
    traffic = packet_sniffer.get_packet()
    is_simulated = False
    
    # 2. If no real packet, simulate
    if not traffic:
        traffic, _ = simulate_network_traffic()
        is_simulated = True
        
        # Update RQA with simulated packet length
        packet_sniffer.rqa.add_data_point(traffic['src_bytes'])
        rqa_metrics = packet_sniffer.rqa.calculate_rqa()
        traffic['rqa_rr'] = rqa_metrics['rr']
        traffic['rqa_det'] = rqa_metrics['det']
    
    # 3. Predict
    prediction = predict_traffic(traffic)
    
    # 4. Prepare Log Entry
    log_entry = {
        'timestamp': traffic['timestamp'],
        'src_ip': traffic['src_ip'],
        'dst_ip': traffic['dst_ip'],
        'protocol': traffic.get('protocol_type', 'unknown'),
        'service': traffic.get('service', 'unknown'),
        'prediction': prediction['prediction'],
        'confidence': prediction['confidence'],
        'threat_level': prediction.get('threat_level', 'Low'),
        'blocked': False,
        'rqa_rr': traffic.get('rqa_rr', 0),
        'rqa_det': traffic.get('rqa_det', 0)
    }
    
    # 5. Handle Malicious Traffic
    if prediction.get('is_malicious', False):
        attack_detected = True
        database.block_ip(traffic['src_ip'], reason=f"Detected {prediction['prediction']}")
        log_entry['blocked'] = True
    
    # 6. Log to Database
    database.log_traffic(log_entry)
    
    # 7. Fetch recent logs for UI
    recent_logs = database.get_recent_logs(limit=10)
    blocked_count = database.get_stats()['blocked_count']
    
    return jsonify({
        'log_entry': log_entry,
        'total_blocked': blocked_count,
        'recent_logs': recent_logs,
        'is_simulated': is_simulated
    })

@app.route('/api/statistics')
def statistics():
    stats = database.get_stats()
    
    # Calculate detection rate
    total = stats['total_traffic']
    malicious = stats['malicious_count']
    detection_rate = (malicious / total * 100) if total > 0 else 0
    
    return jsonify({
        'total_traffic': total,
        'malicious_count': malicious,
        'blocked_ips': stats['blocked_count'],
        'detection_rate': detection_rate,
        'threat_distribution': stats['threat_distribution'],
        'blocked_ip_list': database.get_blocked_ips()[:10]
    })

@app.route('/api/generate-report')
def generate_report():
    stats = database.get_stats()
    recent_logs = database.get_recent_logs(limit=50)
    blocked_ips = database.get_blocked_ips()
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'summary': {
            'total_packets_analyzed': stats['total_traffic'],
            'threats_detected': stats['malicious_count'],
            'ips_blocked': stats['blocked_count'],
            'system_status': 'Under Attack' if attack_detected else 'Secure'
        },
        'performance_impact': {
            'avg_cpu_before': np.mean(system_metrics_before['cpu']) if system_metrics_before['cpu'] else 0,
            'avg_cpu_after': np.mean(system_metrics_after['cpu']) if system_metrics_after['cpu'] else 0,
            'avg_memory_before': np.mean(system_metrics_before['memory']) if system_metrics_before['memory'] else 0,
            'avg_memory_after': np.mean(system_metrics_after['memory']) if system_metrics_after['memory'] else 0
        },
        'recent_threats': [log for log in recent_logs if log['prediction'] != 'Normal'],
        'blocked_ips': blocked_ips
    }
    
    os.makedirs('reports', exist_ok=True)
    report_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return jsonify({'report': report, 'saved_to': report_file})

@app.route('/api/reset')
def reset_system():
    global attack_detected, system_metrics_before, system_metrics_after
    
    attack_detected = False
    system_metrics_before = {'cpu': [], 'memory': [], 'network': []}
    system_metrics_after = {'cpu': [], 'memory': [], 'network': []}
    
    # Note: We do NOT clear the database on reset, only the session state
    
    return jsonify({'status': 'success', 'message': 'System session reset (Database preserved)'})

if __name__ == '__main__':
    print("🚀 Starting Cybersecurity IDS Dashboard (Major Project Edition)...")
    
    # Start Sniffer
    packet_sniffer.start()
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False) # use_reloader=False to prevent double sniffer threads
    finally:
        packet_sniffer.stop()