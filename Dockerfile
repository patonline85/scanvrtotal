FROM python:3.9-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Copy tệp yêu cầu và cài đặt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn
COPY . .

# Chạy ứng dụng qua Gunicorn (để chịu tải tốt hơn chạy python chay)
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]