from flask import Flask, redirect, request, session

from youtube import Youtube

app = Flask(__name__)

ytClient = Youtube()

@app.route('/')
def authRequest():
  authorization_url = ytClient.authRequest()
  return redirect(authorization_url)
  
@app.route('/auth')
def auth():
  print(session)
  state = session['state']
  credentials = ytClient.auth(state)

  session['credentials'] = {
    'token': credentials.token,
    'refresh_token': credentials.refresh_token,
    'token_uri': credentials.token_uri,
    'client_id': credentials.client_id,
    'client_secret': credentials.client_secret,
    'scopes': credentials.scopes}

  return credentials.token
  