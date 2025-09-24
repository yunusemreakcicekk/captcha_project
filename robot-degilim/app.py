from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_bcrypt import Bcrypt
import os
import re
import time
import random
import json
from datetime import datetime, timedelta, timezone
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from captcha.image import ImageCaptcha
import string
from io import BytesIO
from flask import send_file
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'degistir-bunu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(get_remote_address, app=app)
BAN_DURATION = 180  # 180 saniye = 3 dakika
MAX_ATTEMPTS = 7


MERDIVEN_SORULARI = [
    {
        "seviye": 1,
        "soru": "Aşağıdakilerden hangisi Python'da yorum satırı oluşturur?",
        "cevaplar": ["// Yorum", "# Yorum"],
        "dogru_cevap": 1
    },
    {
        "seviye": 2,
        "soru": "Python'da liste oluşturmak için hangi semboller kullanılır?",
        "cevaplar": ["()", "[]", "{}"],
        "dogru_cevap": 1
    },
    {
        "seviye": 3,
        "soru": "Hangisi Flask için doğru bir import ifadesidir?",
        "cevaplar": ["import flask", "from Flask import Flask", "from flask import Flask", "import Flask from flask"],
        "dogru_cevap": 2
    },
    {
        "seviye": 4,
        "soru": "SQLite veritabanı dosyalarının uzantısı nedir?",
        "cevaplar": [".sql", ".db", ".sqlite", ".data"],
        "dogru_cevap": 2
    },
    {
        "seviye": 5,
        "soru": "Python'da bir fonksiyon tanımlamak için hangi anahtar kelime kullanılır?",
        "cevaplar": ["func", "def", "function", "define"],
        "dogru_cevap": 1
    },
    {
        "seviye": 6,
        "soru": "Flask'ta route tanımlamak için hangi dekoratör kullanılır?",
        "cevaplar": ["@path", "@app.route", "@route", "@app.path"],
        "dogru_cevap": 1
    },
    {
        "seviye": 7,
        "soru": "Python'da bir dosyayı okumak için hangi mod kullanılır?",
        "cevaplar": ["'r'", "'w'", "'a'", "'x'"],
        "dogru_cevap": 0
    }
]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    merdiven_seviye = db.Column(db.Integer, default=0)
    merdiven_deneme = db.Column(db.Integer, default=0)
    merdiven_combo = db.Column(db.Integer, default=0)
    merdiven_tamamlandi = db.Column(db.Boolean, default=False)

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    ban_start = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    ban_end = db.Column(db.DateTime, nullable=False)
    attempt_count = db.Column(db.Integer, default=0)
    reason = db.Column(db.String(200))
    
    def is_active(self):
        current_time = datetime.now(timezone.utc)
        if self.ban_end.tzinfo is None:
            ban_end_aware = self.ban_end.replace(tzinfo=timezone.utc)
        else:
            ban_end_aware = self.ban_end
        return current_time < ban_end_aware
    
    def remaining_time(self):
        current_time = datetime.now(timezone.utc)
        if self.ban_end.tzinfo is None:
            ban_end_aware = self.ban_end.replace(tzinfo=timezone.utc)
        else:
            ban_end_aware = self.ban_end
            
        if current_time < ban_end_aware:
            remaining = (ban_end_aware - current_time).seconds
            return f"{remaining // 60}:{remaining % 60:02d}"
        return "0:00"

class FailedAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    username_attempted = db.Column(db.String(150))
    user_agent = db.Column(db.String(200))
    attempt_type = db.Column(db.String(50))  # 'login', 'puzzle'

class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    log_time = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    user_agent = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, details=None, user_id=None):
    ip = get_remote_address()
    user_agent = request.headers.get('User-Agent', 'Bilinmiyor')
    
    log_entry = LogEntry(
        ip_address=ip,
        action=action,
        details=details,
        user_agent=user_agent,
        user_id=user_id
    )
    db.session.add(log_entry)
    db.session.commit()
    
    app.logger.info(f"{action} - IP: {ip} - Details: {details}")

def cleanup_old_records():
    current_time = datetime.now(timezone.utc)
    

    one_hour_ago = current_time - timedelta(hours=1)
    FailedAttempt.query.filter(FailedAttempt.attempt_time < one_hour_ago).delete()
    

    expired_bans = BannedIP.query.all()
    for ban in expired_bans:
        if ban.ban_end.tzinfo is None:
            ban_end_aware = ban.ban_end.replace(tzinfo=timezone.utc)
        else:
            ban_end_aware = ban.ban_end
        
        if current_time >= ban_end_aware:
            db.session.delete(ban)
    
  
    thirty_days_ago = current_time - timedelta(days=30)
    LogEntry.query.filter(LogEntry.log_time < thirty_days_ago).delete()
    
    db.session.commit()

def is_password_strong(password):
    if len(password) < 7:
        return False, "Şifre en az 7 karakter olmalıdır"
    
    if not re.search(r'[A-Z]', password):
        return False, "Şifre en az bir büyük harf içermelidir"
    
    if not re.search(r'[a-z]', password):
        return False, "Şifre en az bir küçük harf içermelidir"
    
    if not re.search(r'[0-9]', password):
        return False, "Şifre en az bir rakam içermelidir"
    
    return True, "Şifre yeterince güçlü"

@app.before_request
def check_ban_status():
    if request.endpoint == 'login':
        ip = get_remote_address()
        current_time = datetime.now(timezone.utc)
        
        active_ban = BannedIP.query.filter(
            BannedIP.ip_address == ip
        ).first()
        
        if active_ban:

            if active_ban.ban_end.tzinfo is None:
                ban_end_aware = active_ban.ban_end.replace(tzinfo=timezone.utc)
            else:
                ban_end_aware = active_ban.ban_end
            
            if current_time >= ban_end_aware:
                db.session.delete(active_ban)
                db.session.commit()
            else:
                return render_template('banned.html', 
                                     ip=ip, 
                                     remaining_time=active_ban.remaining_time(), 
                                     ban_end=active_ban.ban_end), 403
        
        three_minutes_ago = current_time - timedelta(minutes=3)
        recent_attempts = FailedAttempt.query.filter(
            FailedAttempt.ip_address == ip,
            FailedAttempt.attempt_time >= three_minutes_ago
        ).count()
        
        if recent_attempts >= MAX_ATTEMPTS and request.method == 'POST':
            ban_end = current_time + timedelta(seconds=BAN_DURATION)
            banned_ip = BannedIP(
                ip_address=ip,
                ban_end=ban_end,
                attempt_count=recent_attempts,
                reason="7 başarısız giriş denemesi"
            )
            db.session.add(banned_ip)
            db.session.commit()
            log_action("IP Banlandı", f"IP: {ip}, Deneme sayısı: {recent_attempts}")
            
            return render_template('banned.html', 
                                 ip=ip, 
                                 remaining_time=BAN_DURATION//60, 
                                 ban_end=ban_end), 429

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        user_captcha = request.form['captcha'].strip().upper()
        if user_captcha != session.get('captcha_text', ''):
            flash('CAPTCHA hatalı!', 'danger')
            log_action("CAPTCHA Hatası", "Kayıt sırasında CAPTCHA doğrulaması başarısız")
            return redirect(request.url)

        username = request.form['username'].strip()
        password = request.form['password']

        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Kullanıcı adı zaten var', 'danger')
            return redirect(url_for('register'))

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=pw_hash)
        db.session.add(user)
        db.session.commit()
        
        flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
        log_action("Kayıt Başarılı", f"Kullanıcı: {username}")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per minute", methods=["POST"])  
def login():
    ip = get_remote_address()
    current_time = datetime.now(timezone.utc)

   
    active_ban = BannedIP.query.filter(
        BannedIP.ip_address == ip, 
        BannedIP.ban_end > current_time
    ).first()
    
    if active_ban:
        remaining = active_ban.remaining_time()
        log_action("Banlı IP Giriş Denemesi", f"IP: {ip}, Kalan süre: {remaining}")
        return render_template('banned.html', 
                             ip=ip, 
                             remaining_time=remaining, 
                             ban_end=active_ban.ban_end), 403

    
    if request.method == 'GET':
    
        three_minutes_ago = current_time - timedelta(minutes=3)
        recent_attempts = FailedAttempt.query.filter(
            FailedAttempt.ip_address == ip,
            FailedAttempt.attempt_time >= three_minutes_ago
        ).count()
        
        remaining_attempts = MAX_ATTEMPTS - recent_attempts
        if remaining_attempts < 0:
            remaining_attempts = 0

        
        correct_target = random.randint(1, 3)
        session['puzzle_answer'] = str(correct_target)

        return render_template('login.html', 
                             remaining_attempts=remaining_attempts,
                             correct_target=correct_target)

    
    user_captcha = request.form.get('captcha', '').strip().upper()
    stored_captcha = session.get('captcha_text', '')
    
    if user_captcha != stored_captcha:
        
        failed_attempt = FailedAttempt(
            ip_address=ip,
            username_attempted=request.form.get('username', ''),
            user_agent=request.headers.get('User-Agent', ''),
            attempt_type='captcha'
        )
        db.session.add(failed_attempt)
        db.session.commit()
        
        flash('CAPTCHA hatalı!', 'danger')
        return redirect(url_for('login'))


    puzzle_answer = request.form.get('puzzle_answer', '')
    stored_puzzle = session.get('puzzle_answer', '')
    
    if puzzle_answer != stored_puzzle:
        
        failed_attempt = FailedAttempt(
            ip_address=ip,
            username_attempted=request.form.get('username', ''),
            user_agent=request.headers.get('User-Agent', ''),
            attempt_type='puzzle'
        )
        db.session.add(failed_attempt)
        db.session.commit()
        
        flash('Puzzle tamamlanamadı!', 'danger')
        return redirect(url_for('login'))


    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not bcrypt.check_password_hash(user.password, password):
     
        failed_attempt = FailedAttempt(
            ip_address=ip,
            username_attempted=username,
            user_agent=request.headers.get('User-Agent', ''),
            attempt_type='login'
        )
        db.session.add(failed_attempt)
        db.session.commit()
        
        flash('Kullanıcı adı veya şifre hatalı!', 'danger')
        return redirect(url_for('login'))

  
    FailedAttempt.query.filter_by(ip_address=ip).delete()
    db.session.commit()
    
    login_user(user)
    flash('Giriş başarılı! Hoşgeldiniz.', 'success')
    log_action("Başarılı Giriş", f"Kullanıcı: {username}", user_id=user.id)
    return redirect(url_for('dashboard'))

@app.route('/merdiven-oyunu')
@login_required
def merdiven_oyunu():
    
    current_level = current_user.merdiven_seviye
    attempts_left = 10 - current_user.merdiven_deneme
    combo = current_user.merdiven_combo
    
  
    if current_level >= len(MERDIVEN_SORULARI):
        current_user.merdiven_tamamlandi = True
        db.session.commit()
        return render_template('merdiven_tamam.html', 
                             username=current_user.username,
                             level=current_level)
    
    
    current_question = MERDIVEN_SORULARI[current_level]
    
    return render_template('merdiven_oyunu.html', 
                         question=current_question,
                         level=current_level + 1,
                         attempts_left=attempts_left,
                         combo=combo)

@app.route('/merdiven-cevap', methods=['POST'])
@login_required
def merdiven_cevap():
    cevap = int(request.form.get('cevap', -1))
    current_level = current_user.merdiven_seviye
    
    if current_level >= len(MERDIVEN_SORULARI):
        return jsonify({'tamam': True})
    
    current_question = MERDIVEN_SORULARI[current_level]
    dogru_cevap = current_question['dogru_cevap']
    
   
    current_user.merdiven_deneme += 1
    
    if cevap == dogru_cevap:
      
        current_user.merdiven_combo += 1
        current_user.merdiven_seviye += 1
        
       
        if current_user.merdiven_combo > 0:
            current_user.merdiven_deneme = max(0, current_user.merdiven_deneme - 1)
        
        
        if current_user.merdiven_seviye >= len(MERDIVEN_SORULARI):
            current_user.merdiven_tamamlandi = True
            log_action("Merdiven Tamamlandı", 
                      f"Kullanıcı {current_user.username} merdiven oyununu tamamladı.",
                      user_id=current_user.id)
        
        db.session.commit()
        
        log_action("Merdiven Başarı", 
                  f"Kullanıcı {current_user.username} seviye {current_level + 1}'i geçti. Combo: {current_user.merdiven_combo}",
                  user_id=current_user.id)
        
        return jsonify({
            'dogru': True,
            'yeni_seviye': current_user.merdiven_seviye,
            'combo': current_user.merdiven_combo,
            'deneme_hakki': 10 - current_user.merdiven_deneme
        })
    else:
      
        current_user.merdiven_combo = 0
        
       
        if current_user.merdiven_deneme >= 10:
            current_user.merdiven_seviye = 0
            current_user.merdiven_deneme = 0
            db.session.commit()
            
            log_action("Merdiven Başarısız", 
                      f"Kullanıcı {current_user.username} seviye {current_level + 1}'de başarısız oldu ve sıfırlandı",
                      user_id=current_user.id)
            
            return jsonify({
                'dogru': False,
                'sifirla': True,
                'mesaj': 'Deneme hakkınız kalmadı. Başa döndünüz.'
            })
        
        db.session.commit()
        
        log_action("Merdiven Yanlış Cevap", 
                  f"Kullanıcı {current_user.username} seviye {current_level + 1}'de yanlış cevap verdi",
                  user_id=current_user.id)
        
        return jsonify({
            'dogru': False,
            'deneme_hakki': 10 - current_user.merdiven_deneme,
            'mesaj': 'Yanlış cevap!'
        })
@app.route('/merdiven-sifirla')
@login_required
def merdiven_sifirla():
   
    current_user.merdiven_seviye = 0
    current_user.merdiven_deneme = 0
    current_user.merdiven_combo = 0
    current_user.merdiven_tamamlandi = False
    db.session.commit()
    
    log_action("Merdiven Sıfırlandı", f"Kullanıcı {current_user.username} merdiven oyununu sıfırladı", user_id=current_user.id)
    return redirect(url_for('merdiven_oyunu'))

@app.route('/admin')
@login_required
def admin():
    if current_user.username != 'admin':
        flash("Bu sayfaya erişim yetkiniz yok!", "danger")
        return redirect(url_for('dashboard'))

    
    active_bans = BannedIP.query.filter(
        BannedIP.ban_end > datetime.now(timezone.utc)
    ).all()
    
   
    recent_logs = LogEntry.query.order_by(LogEntry.log_time.desc()).limit(100).all()
    
    
    user_stats = User.query.all()
    

    today = datetime.now(timezone.utc).date()
    today_logins = LogEntry.query.filter(
        LogEntry.action == "Başarılı Giriş",
        db.func.date(LogEntry.log_time) == today
    ).all()
    
   
    tamamlayanlar = User.query.filter_by(merdiven_tamamlandi=True).all()
    
    
    ip_list = []
    for ban in active_bans:
        ip_list.append({
            'ip': ban.ip_address,
            'count': ban.attempt_count,
            'remaining': ban.remaining_time(),
            'ban_end': ban.ban_end,
            'reason': ban.reason
        })
    
    
    merdiven_istatistik = []
    for user in user_stats:
        if user.merdiven_seviye > 0:
            merdiven_istatistik.append({
                'username': user.username,
                'seviye': user.merdiven_seviye,
                'combo': user.merdiven_combo,
                'tamamlandi': user.merdiven_tamamlandi
            })

    return render_template('admin.html', 
                         ip_list=ip_list, 
                         logs=recent_logs,
                         merdiven_istatistik=merdiven_istatistik,
                         today_logins=today_logins,
                         tamamlayanlar=tamamlayanlar)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', 
                         merdiven_seviye=current_user.merdiven_seviye,
                         merdiven_combo=current_user.merdiven_combo)

@app.route('/logout')
@login_required
def logout():
    log_action("Çıkış Yapıldı", f"Kullanıcı: {current_user.username}", user_id=current_user.id)
    logout_user()
    flash('Çıkış yapıldı.', 'info')
    return redirect(url_for('login'))
    
def generate_captcha_text(length=5):
    letters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))
   
@app.errorhandler(429)
def ratelimit_handler(e):
    ip = get_remote_address()
    current_time = datetime.now(timezone.utc)

    active_ban = BannedIP.query.filter(
        BannedIP.ip_address == ip, 
        BannedIP.ban_end > current_time
    ).first()
    
    if active_ban:
        ban_remaining = active_ban.remaining_time()
        return f"⚠ Çok fazla istek yaptınız! IP: {ip} | Kalan ban süresi: {ban_remaining}", 429
    
    ban_end = current_time + timedelta(seconds=BAN_DURATION)
    banned_ip = BannedIP(
        ip_address=ip, 
        ban_end=ban_end,
        attempt_count=1,
        reason="Rate limit aşımı"
    )
    db.session.add(banned_ip)
    db.session.commit()
    
    log_action("Rate Limit Banı", f"IP: {ip}, Sebep: Rate limit aşımı")
    return f"⚠ Çok fazla istek yaptınız! IP: {ip} | Ban süresi: {BAN_DURATION} saniye", 429

@app.route('/captcha')
def captcha():
    captcha_text = generate_captcha_text()
    session['captcha_text'] = captcha_text
    image = ImageCaptcha()
    data = image.generate(captcha_text)
    return send_file(BytesIO(data.read()), mimetype='image/png')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        cleanup_old_records()
    app.run(debug=True)