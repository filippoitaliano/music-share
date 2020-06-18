import os
import functools
import pickle
import google.oauth2.credentials
import google_auth_oauthlib.flow
import sqlite3
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db
from dotenv import load_dotenv


load_dotenv()


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    db = get_db()

    error = None
    if not username:
      error = 'Username is required.'
    elif not password:
      error = 'Password is required.'
    elif db.execute(
      'SELECT id FROM user WHERE username = ?', (username,)
    ).fetchone() is not None:
      error = 'User {} is already registered.'.format(username)

    if error is None:
      db.execute(
        'INSERT INTO user (username, password) VALUES (?, ?)',
        (username, generate_password_hash(password))
      )
      db.commit()
      return redirect(url_for('auth.login'))

    flash(error)

  return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    error = None
    user = db.execute(
      'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()

    if user is None:
      error = 'Incorrect username.'
    elif not check_password_hash(user['password'], password):
      error = 'Incorrect password.'

    if error is None:
      session.clear()
      session['user_id'] = user['id']
      return redirect(url_for('dashboard.dashboard'))

    flash(error)

  return render_template('auth/login.html')


@bp.route('/connect-youtube', methods=["GET"])
def connect_youtube():
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  client_config = {
    "web": {
      "client_id": os.getenv("CLIENT_ID"),
      "project_id": os.getenv("PROJECT_ID"),
      "auth_uri": os.getenv("AUTH_URI"),
      "token_uri": os.getenv("TOKEN_URI"),
      "auth_provider_x509_cert_url": os.getenv("AUTH_PROVIDER_X509_CERT_URL"),
      "client_secret": os.getenv("CLIENT_SECRET"),
      "redirect_uris": [os.getenv("REDIRECT_URIS")],
    }
  }

  flow = google_auth_oauthlib.flow.Flow.from_client_config(
    client_config, ['https://www.googleapis.com/auth/youtube.readonly']
  )

  flow.redirect_uri = 'http://127.0.0.1:5000/auth/connect-youtube-continue'

  authorization_url, state = flow.authorization_url(
  access_type='offline',
  include_granted_scopes='true')

  return redirect(authorization_url, 302)


@bp.route('/connect-youtube-continue', methods=["GET"])
def connect_youtube_continue():
  # error = request.args.get('error')
  # code = request.args.get('code')

  root = os.path.realpath(current_app.root_path)
  client_secret_url = os.path.join(root, "static/data", "client_secret.json")

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
  client_secret_url,
  ['https://www.googleapis.com/auth/youtube.readonly'])

  flow.redirect_uri = 'http://127.0.0.1:5000/auth/connect-youtube-continue'
  flow.fetch_token(authorization_response=request.url)

  values = {
    'youtube_credentials': sqlite3.Binary(pickle.dumps(flow.credentials, protocol=2)),
    'user_id': session['user_id'],
  }

  db = get_db()
  db.execute("UPDATE user SET youtube_credentials=(:youtube_credentials) WHERE id=(:user_id)", values)
  db.commit()

  return redirect('/dashboard', 302)


@bp.before_app_request
def load_logged_in_user():
  user_id = session.get('user_id')

  if user_id is None:
    g.user = None
  else:
    g.user = get_db().execute(
      'SELECT * FROM user WHERE id = ?', (user_id,)
    ).fetchone()


@bp.route('/logout')
def logout():
  session.clear()
  return redirect(url_for('index'))


def login_required(view):
  @functools.wraps(view)
  def wrapped_view(**kwargs):
    if g.user is None:
      return redirect(url_for('auth.login'))

    return view(**kwargs)

  return wrapped_view

