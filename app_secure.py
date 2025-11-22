"""
Flask Application with CIA Triad Implementation
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pickle
import re
import hashlib
import logging
import os
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension

# ============================================================================
# CONFIDENTIALITY: Protect data from unauthorized access
# ============================================================================

# Configure secure logging (mask sensitive data) (in case any sensitive information)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

def mask_url_for_logging(url):
    """Mask sensitive parts of URL in logs (CONFIDENTIALITY)"""
    if '@' in url:  # Email in URL
        parts = url.split('@')
        if len(parts) == 2:
            return parts[0][:2] + '***@' + parts[1]
    if '?' in url and 'token=' in url.lower():
        # Mask tokens in query strings
        url = re.sub(r'token=([^&]+)', r'token=***', url, flags=re.IGNORECASE)
    return url

# ============================================================================
# INTEGRITY: Ensure data accuracy and prevent unauthorized modification
# ============================================================================

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of file (INTEGRITY)"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {filepath}: {e}")
        return None

def verify_model_integrity(model_path, expected_hash=None):
    """Verify model file hasn't been tampered with (INTEGRITY)"""
    if expected_hash is None:
        # If no expected hash provided, skip verification (not recommended for production)
        logging.warning(f"No expected hash provided for {model_path} - skipping integrity check")
        return True
    
    current_hash = calculate_file_hash(model_path)
    if current_hash != expected_hash:
        logging.error(f"Model integrity check failed for {model_path}")
        logging.error(f"Expected: {expected_hash}")
        logging.error(f"Got: {current_hash}")
        raise ValueError("Model file integrity check failed - file may have been tampered with")
    
    logging.info(f"Model integrity verified for {model_path}")
    return True

def validate_url_integrity(url):
    """Enhanced URL validation (INTEGRITY)"""
    # Check URL length (prevent buffer overflow attacks)
    if len(url) > 2048:
        raise ValueError("URL too long (max 2048 characters)")
    
    # Check for SQL injection patterns
    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            logging.warning(f"Suspicious SQL pattern detected in URL: {url[:50]}...")
            raise ValueError("Suspicious input detected - SQL injection pattern found")
    
    # Check for XSS patterns
    xss_patterns = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onclick=",
        r"onload=",
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            logging.warning(f"Suspicious XSS pattern detected in URL: {url[:50]}...")
            raise ValueError("Suspicious input detected - XSS pattern found")
    
    # Validate URL format
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'https://' + url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format - no domain found")
    except Exception as e:
        logging.warning(f"URL parsing failed: {e}")
        raise ValueError(f"Invalid URL format: {str(e)}")
    
    return True

# Load models with integrity verification
MODEL_HASH = os.getenv('MODEL_HASH', None)  # Expected SHA-256 hash
VECTORIZER_HASH = os.getenv('VECTORIZER_HASH', None)

try:
    # Verify model integrity (optional - requires hash in .env)
    if MODEL_HASH:
        verify_model_integrity("phishing.pkl", MODEL_HASH)
    if VECTORIZER_HASH:
        verify_model_integrity("vectorizer.pkl", VECTORIZER_HASH)
    
    # Load models
    vector = pickle.load(open("vectorizer.pkl", 'rb'))
    model = pickle.load(open("phishing.pkl", 'rb'))
    logging.info("Models loaded successfully")
except FileNotFoundError as e:
    logging.error(f"Model file not found: {e}")
    vector = None
    model = None
except Exception as e:
    logging.error(f"Error loading models: {e}")
    vector = None
    model = None

# ============================================================================
# AVAILABILITY: Ensure system is accessible when needed
# ============================================================================

# Rate limiting (AVAILABILITY - prevent DoS)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour", "20 per minute"],
    storage_uri="memory://"  
)

# Health check endpoint (AVAILABILITY)
@app.route("/health", methods=['GET'])
def health_check():
    """Health check endpoint for monitoring availability"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "models": {
                "phishing_model": model is not None,
                "vectorizer": vector is not None
            }
        }
        
        if model is None or vector is None:
            health_status["status"] = "degraded"
            return jsonify(health_status), 503
        
        # Test prediction to verify models work
        try:
            test_url = "example.com"
            test_prediction = model.predict(vector.transform([test_url]))
            health_status["test_prediction"] = "success"
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
            return jsonify(health_status), 503
        
        return jsonify(health_status), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 503

# ============================================================================
# Helper Functions
# ============================================================================

def is_browser_protocol(url):
    """Check if URL is a browser protocol (chrome://, about:, file://, etc.)"""
    browser_protocols = [
        'chrome://', 'chrome-extension://', 'moz-extension://',
        'about:', 'file://', 'data:', 'javascript:', 'edge://', 'brave://'
    ]
    url_lower = url.lower().strip()
    return any(url_lower.startswith(proto) for proto in browser_protocols)

def is_internal_url(url):
    """Check if URL is localhost, internal IP, or local domain"""
    cleaned = re.sub(r'^https?://(www\.)?', '', url).strip().lower()
    cleaned = re.sub(r'^ftp://', '', cleaned).strip()
    cleaned = re.sub(r':\d+$', '', cleaned).strip()
    
    if '/' in cleaned:
        cleaned = cleaned.split('/')[0]
    
    internal_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "localhost.localdomain"]
    if cleaned in internal_hosts:
        return True
    
    # Private IP ranges (RFC 1918)
    if cleaned.startswith("10."):
        return True
    if cleaned.startswith("172."):
        parts = cleaned.split('.')
        if len(parts) >= 2:
            try:
                if 16 <= int(parts[1]) <= 31:
                    return True
            except:
                pass
    if cleaned.startswith("192.168.") or cleaned.startswith("127.") or cleaned.startswith("169.254."):
        return True
    if cleaned.endswith(".local") or ".local." in cleaned or cleaned.endswith(".localhost"):
        return True
    
    return False

# ============================================================================
# Main API Endpoint (with CIA Triad implementation)
# ============================================================================

@app.route("/api/check", methods=['POST'])
@limiter.limit("10 per minute")  # AVAILABILITY: Rate limiting
def check_url_api():
    """
    API endpoint for Chrome extension - returns JSON response
    Implements CIA Triad:
    - CONFIDENTIALITY: Logs masked URLs, no sensitive data in responses
    - INTEGRITY: Input validation, model integrity checks
    - AVAILABILITY: Rate limiting, error handling, graceful degradation
    """
    client_ip = request.remote_addr
    request_start_time = datetime.now()
    
    try:
        # Get URL from JSON or form data
        if request.is_json:
            data = request.get_json()
            url = data.get('url', '')
        else:
            url = request.form.get('url', '') or request.args.get('url', '')
        
        if not url:
            logging.warning(f"Empty URL request from {client_ip}")
            return jsonify({
                'success': False,
                'error': 'URL is required',
                'message': 'Please provide a URL to check'
            }), 400
        
        # INTEGRITY: Validate URL integrity
        try:
            validate_url_integrity(url)
        except ValueError as e:
            logging.warning(f"Invalid URL from {client_ip}: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Invalid URL',
                'message': str(e)
            }), 400
        
        # Check browser protocols
        if is_browser_protocol(url):
            result = {
                'success': True,
                'is_phishing': False,
                'message': 'This is a healthy and good website !!',
                'url': url,
                'cleaned_url': url
            }
            masked_url = mask_url_for_logging(url)
            logging.info(f"Request from {client_ip}: {masked_url[:50]}... -> safe (browser protocol)")
            return jsonify(result), 200
        
        # Check internal/localhost URLs
        if is_internal_url(url):
            result = {
                'success': True,
                'is_phishing': False,
                'message': 'This is a healthy and good website !!',
                'url': url,
                'cleaned_url': url
            }
            masked_url = mask_url_for_logging(url)
            logging.info(f"Request from {client_ip}: {masked_url[:50]}... -> safe (internal URL)")
            return jsonify(result), 200
        
        # Clean the URL
        cleaned_url = re.sub(r'^https?://(www\.)?', '', url).strip().lower()
        cleaned_url = re.sub(r'^ftp://', '', cleaned_url).strip()
        
        if not cleaned_url or len(cleaned_url) < 3:
            result = {
                'success': True,
                'is_phishing': True,
                'message': 'This is a Phishing website !!',
                'url': url,
                'cleaned_url': cleaned_url
            }
            masked_url = mask_url_for_logging(url)
            logging.info(f"Request from {client_ip}: {masked_url[:50]}... -> phishing (invalid URL)")
            return jsonify(result), 200
        
        # AVAILABILITY: Check if models are loaded
        if model is None or vector is None:
            logging.error("Models not loaded - service degraded")
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable',
                'message': 'Models not loaded. Please check server status.'
            }), 503
        
        # Make prediction
        try:
            prediction = model.predict(vector.transform([cleaned_url]))[0]
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return jsonify({
                'success': False,
                'error': 'Prediction failed',
                'message': 'An error occurred while processing the URL'
            }), 500
        
        # Format response
        if prediction == 'bad':
            result = {
                'success': True,
                'is_phishing': True,
                'message': 'This is a Phishing website !!',
                'url': url,
                'cleaned_url': cleaned_url
            }
        elif prediction == 'good':
            result = {
                'success': True,
                'is_phishing': False,
                'message': 'This is a healthy and good website !!',
                'url': url,
                'cleaned_url': cleaned_url
            }
        else:
            result = {
                'success': False,
                'error': 'Unknown prediction result',
                'message': 'Something went wrong !!',
                'url': url
            }
        
        # CONFIDENTIALITY: Log with masked URL
        masked_url = mask_url_for_logging(url)
        request_duration = (datetime.now() - request_start_time).total_seconds()
        logging.info(f"Request from {client_ip}: {masked_url[:50]}... -> {prediction} (took {request_duration:.3f}s)")
        
        return jsonify(result), 200
        
    except Exception as e:
        masked_url = mask_url_for_logging(url) if 'url' in locals() else 'unknown'
        logging.error(f"Error processing request from {client_ip}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while processing the request'
        }), 500


@app.route("/api/stats", methods=['GET'])
@limiter.limit("10 per minute")
def get_stats():
    """Get basic statistics (requires authentication in production)"""
    # In production, add authentication here
    stats = {
        "status": "operational" if (model and vector) else "degraded",
        "models_loaded": {
            "phishing_model": model is not None,
            "vectorizer": vector is not None
        },
        "timestamp": datetime.now().isoformat()
    }
    return jsonify(stats), 200


if __name__ == "__main__":
    # CONFIDENTIALITY: Disable debug mode in production
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    if not debug_mode:
        # In production, use HTTPS
        # app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=False)
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        app.run(debug=True, port=5000)

