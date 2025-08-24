from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messenger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Friend request table
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')

# Messages table
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(100), default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    users = User.query.filter(User.id != current_user.id).all()
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.desc()).all()
    requests = FriendRequest.query.filter_by(to_user=current_user.id, status='pending').all()
    return render_template('index.html', users=users, messages=messages, requests=requests)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/send_friend_request/<int:user_id>')
@login_required
def send_friend_request(user_id):
    if FriendRequest.query.filter_by(from_user=current_user.id, to_user=user_id).first():
        flash('Request already sent')
        return redirect(url_for('index'))
    request_obj = FriendRequest(from_user=current_user.id, to_user=user_id)
    db.session.add(request_obj)
    db.session.commit()
    flash('Friend request sent')
    return redirect(url_for('index'))

@app.route('/accept_request/<int:req_id>')
@login_required
def accept_request(req_id):
    req = FriendRequest.query.get(req_id)
    if req and req.to_user == current_user.id:
        req.status = 'accepted'
        db.session.commit()
        flash('Friend request accepted')
    return redirect(url_for('index'))

@app.route('/delete_request/<int:req_id>')
@login_required
def delete_request(req_id):
    req = FriendRequest.query.get(req_id)
    if req and req.to_user == current_user.id:
        db.session.delete(req)
        db.session.commit()
        flash('Friend request deleted')
    return redirect(url_for('index'))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = int(request.form['receiver_id'])
    content = request.form['message']
    msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    flash('Message sent')
    return redirect(url_for('index'))

@app.route('/delete_message/<int:msg_id>')
@login_required
def delete_message(msg_id):
    msg = Message.query.get(msg_id)
    if msg and msg.sender_id == current_user.id:
        db.session.delete(msg)
        db.session.commit()
        flash('Message deleted')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)