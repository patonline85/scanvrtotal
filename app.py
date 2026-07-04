import os, hashlib, requests, base64
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
# Đọc API Key từ biến môi trường (sẽ truyền qua Portainer)
VT_API_KEY = os.environ.get('VT_API_KEY')

# ==========================================
# CẤU HÌNH BẢO MẬT: GIỚI HẠN DUNG LƯỢNG UPLOAD
# ==========================================
# Giới hạn toàn bộ request body (bao gồm cả file) ở mức 32 MB
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024 

# Bắt lỗi khi người dùng cố tình gửi file > 32MB và trả về định dạng JSON
@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_exceeded(error):
    return jsonify({
        "error": "Tệp quá lớn. Hệ thống chỉ cho phép tải lên tối đa 32MB để đảm bảo hiệu suất."
    }), 413
    
def get_sha256(file_stream):
    sha256_hash = hashlib.sha256()
    file_stream.seek(0)
    for byte_block in iter(lambda: file_stream.read(4096), b""):
        sha256_hash.update(byte_block)
    file_stream.seek(0) # Reset con trỏ file sau khi đọc hash
    return sha256_hash.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

# ==========================================
# 1. API QUÉT TỆP TIN (FILE)
# ==========================================
@app.route('/scan', methods=['POST'])
def scan():
    if not VT_API_KEY:
        return jsonify({"error": "Chưa cấu hình VT_API_KEY trên Server!"})
    
    if 'file' not in request.files:
        return jsonify({"error": "Không tìm thấy tệp được tải lên."})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Chưa chọn tệp."})

    try:
        # Tính mã SHA-256 để tạo link Web ngay lập tức
        file_hash = get_sha256(file)
        
        # Gửi tệp lên VirusTotal API v3
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        files = {"file": (secure_filename(file.filename), file.stream, file.mimetype)}
        
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
        
        data = response.json()
        analysis_id = data.get("data", {}).get("id")
        
        return jsonify({"status": "success", "analysis_id": analysis_id, "hash": file_hash})
    except requests.exceptions.HTTPError as errh:
        if response.status_code == 413:
            return jsonify({"error": "Tệp quá lớn. API miễn phí giới hạn 32MB."})
        return jsonify({"error": f"Lỗi API: {errh}"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/report', methods=['POST'])
def report():
    analysis_id = request.form.get('analysis_id')
    try:
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        stats = response.json().get("data", {}).get("attributes", {}).get("stats", {})
        
        return jsonify({
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0)
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ==========================================
# 2. API QUÉT LIÊN KẾT (URL) MỚI THÊM
# ==========================================
@app.route('/scan-url', methods=['POST'])
def scan_url():
    if not VT_API_KEY:
        return jsonify({"error": "Chưa cấu hình VT_API_KEY trên Server!"})
    
    target_url = request.form.get('url')
    if not target_url:
        return jsonify({"error": "Chưa nhập URL."})

    try:
        # VirusTotal v3 yêu cầu tạo url_id bằng mã hóa Base64 không có dấu "=" ở cuối
        # Điều này dùng để trả về frontend nhằm tạo link xem chi tiết (https://www.virustotal.com/gui/url/{url_id})
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        
        # Gửi URL lên VirusTotal API v3
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        payload = {"url": target_url} # Gửi dưới dạng x-www-form-urlencoded data
        
        response = requests.post(api_url, data=payload, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        analysis_id = data.get("data", {}).get("id")
        
        return jsonify({"status": "success", "analysis_id": analysis_id, "url_id": url_id})
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": f"Lỗi API VirusTotal: {errh}"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/report-url', methods=['POST'])
def report_url():
    # Điểm đặc biệt của VirusTotal v3 là API lấy Báo cáo (Report) cho URL hay cho File 
    # đều dùng chung một hệ thống "Analyses", nên logic phần này sẽ giống hệt như lấy report cho file.
    analysis_id = request.form.get('analysis_id')
    try:
        api_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        
        stats = response.json().get("data", {}).get("attributes", {}).get("stats", {})
        
        return jsonify({
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0)
        })
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
