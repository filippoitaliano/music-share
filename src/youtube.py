import os
import json

from flask import url_for, request
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors

class Youtube:
  """Class interfacing with YouTube Data API v3"""

  _scopes = ["https://www.googleapis.com/auth/youtube.readonly"]
  _api_service_name = "youtube"
  _api_version = "v3"
  _client_secrets_file = "./youtube_client_secrets.json"
  _api = None

  def __init__(self):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

  def __del__(self):
    del os.environ["OAUTHLIB_INSECURE_TRANSPORT"]

  def authRequest(self):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      self._client_secrets_file,
      ['https://www.googleapis.com/auth/youtube.force-ssl'])

    flow.redirect_uri = 'http://localhost:5000/auth'

    authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true')

    return authorization_url

  def auth(self, session_state):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      self._client_secrets_file,
      scopes=['https://www.googleapis.com/auth/youtube.force-ssl'],
      state=session_state)

    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # self._api = googleapiclient.discovery.build(
    #   self._api_service_name,
    #   self._api_version,
    #   credentials=credentials
    # )

    return flow.credentials

  def getPlaylistList(self, title_filter):
    if (self._api is None):
      raise TypeError

    request = self._api.playlists().list( # pylint: disable=maybe-no-member
        part="snippet,contentDetails",
        maxResults=25,
        mine=True)
    response = request.execute()
    return list(filter(lambda item: title_filter in item["snippet"]["title"], response["items"])) 