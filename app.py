from flask import Flask, render_template, request, session, redirect, url_for, g
from flask_socketio import SocketIO
import bcrypt
import sqlite3
import json
import time
import os.path

app = Flask(__name__)
app.secret_key = "4Zc5Goi8s7jLK4Y4PCvZpdXZqyBiY7d3nzrAHkdO"
BASE_DIR = app.root_path
db_path = os.path.join(BASE_DIR, "zchat.sqlite")
socketio = SocketIO(app)


def connect_db():
    return sqlite3.connect(db_path)


def query_db(query, args=(), one=False):
    db = getattr(g, 'db', None)
    if db is None:
        db = g.db = connect_db()
    cur = g.db.execute(query, args)
    g.db.commit()
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def check_user(username, password):
    password_in_db = query_db("SELECT password FROM user WHERE username = ?", [username], True)['password']
    return bcrypt.hashpw(password.encode("utf-8"), password_in_db) == password_in_db


def is_logged_in():
    try:
        username = session['username']
    except KeyError:
        return False
    return True


def get_friends(username):
    serialized_friends = query_db("SELECT friends FROM friends WHERE username = ?", [username], True)
    if serialized_friends:
        return set(json.loads(serialized_friends['friends']))
    else:
        return set()


def set_friends(username, friends):
    query_db("UPDATE friends SET friends = ? WHERE username = ?", [json.dumps(list(friends)), username])


@app.before_request
def before_request():
    app.logger.debug(db_path)
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
def index():
    return redirect(url_for('list_friends'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if check_user(request.form['username'], request.form['password']):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password!"
            return render_template("login.html", error=error)
    return render_template("login.html")


@app.route('/add_friend', methods=['GET', 'POST'])
def add_friend():
    if not is_logged_in(): return redirect(url_for('login'))
    if request.method == 'POST':
        friend = request.form['username']
        username = session['username']
        if friend == username:
            return redirect(url_for('list_friends'))
        if query_db("SELECT * FROM user WHERE username = ?", [friend]):
            friends = get_friends(username)
            friends.add(friend)
            set_friends(username, friends)
            friends = get_friends(friend)
            friends.add(username)
            set_friends(friend, friends)
            return redirect(url_for('list_friends'))
        else:
            error = "No such user!"
            return render_template("add-friend.html", error=error)
    return render_template("add-friend.html")


@app.route('/del_friend/<friend>')
def del_friend(friend):
    if not is_logged_in(): return redirect(url_for('login'))
    username = session['username']
    friends = get_friends(username)
    friends.remove(friend)
    set_friends(username, friends)
    friends = get_friends(friend)
    friends.remove(username)
    set_friends(friend, friends)
    return redirect(url_for('list_friends'))


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        query_db("INSERT INTO user(username, password) VALUES (?, ?)",
                 [request.form['username'],
                  bcrypt.hashpw(request.form['password'].encode('utf-8'),
                                bcrypt.gensalt(12))
                  ]
                 )
        query_db("INSERT INTO friends(username) VALUES (?)",
                 [request.form['username']])
        return redirect(url_for('list_users'))
    return render_template("add-user.html")


@app.route('/list_friends')
def list_friends():
    if not is_logged_in(): return redirect(url_for('login'))
    friends = get_friends(session['username'])
    return render_template("list-friends.html", friends=friends)


@app.route('/list_users')
def list_users():
    users = query_db("SELECT username FROM user")
    return render_template("list-users.html", users=users)


def get_messages(username, friend):
    return query_db('SELECT * FROM messages '
                    'WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)) '
                    'ORDER BY timestamp ASC',
                    [username, friend, friend, username])


@app.route('/chat_with/<friend>')
def chat_with(friend):
    if not is_logged_in(): return redirect(url_for('login'))
    username = session['username']
    friends = get_friends(username)
    if friend not in friends:
        return redirect(url_for('list_friends'))
    messages = get_messages(username, friend)
    return render_template('chat.html', messages=messages, friend=friend, username=username)


@socketio.on('fetch messages', namespace='/chat')
def fetch_messages(data):
    data = json.loads(str(data))
    username = session['username']
    friend = data['friend']
    return json.dumps(get_messages(username, friend))


def insert_message(sender, reveiver, content, timestamp):
    query_db('INSERT INTO messages(sender, receiver, content, "timestamp") VALUES(?, ?, ?, ?)',
             [sender, reveiver, content, timestamp])


def send_to_friend(username, friend, content, timestamp):
    room = query_db('SELECT socket FROM user WHERE username = ?', [friend], one=True)['socket']
    print(room)
    if room:
        socketio.emit('push message',
                      json.dumps({'sender': username, 'receiver': friend, 'content': content, 'timestamp': timestamp}),
                      room=room,
                      namespace='/chat')


@socketio.on('send message', namespace='/chat')
def send_message(data):
    data = json.loads(str(data))
    username = session['username']
    friend = data['friend']
    content = data['content']
    timestamp = int(time.time())
    insert_message(username, friend, content, timestamp)
    send_to_friend(username, friend, content, timestamp)
    return json.dumps(get_messages(username, friend))


@socketio.on('connect', namespace='/chat')
def socket_connect():
    query_db('UPDATE user SET socket = ? WHERE username = ?', [request.sid, session['username']])


@socketio.on('disconnect', namespace='/chat')
def test_disconnect():
    query_db('UPDATE user SET socket = "" WHERE username = ?', [session['username']])


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0')
