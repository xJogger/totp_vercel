import os
from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')  # 设置安全的密钥

# 预存储的密码哈希（用实际密码生成后替换）
# from werkzeug.security import generate_password_hash
# print(generate_password_hash('你的密码'))
PASSWORD_HASH      = os.getenv('PASSWORD_HASH')

# 预存储的TOTP密钥
TOTP_SECRET = os.getenv('TOTP_SECRET')

@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    totp = pyotp.TOTP(TOTP_SECRET)
    current_otp = totp.now()
    return render_template('index.html', otp=current_otp)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if check_password_hash(PASSWORD_HASH, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# if __name__ == '__main__':
    # app.run(debug=True)