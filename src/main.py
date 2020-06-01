from youtube import Youtube

def main():
  ytClient = Youtube()
  ytClient.connect()
  ytClient.getPlaylistList('[SPOTIFY]')

main()