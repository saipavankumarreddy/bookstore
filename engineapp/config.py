import os



if os.getenv('SERVER_SOFTWARE', '').startswith('Google App Engine/'):
    app_url = 'www.workwithflask.appspot.com'
else:
    app_url = 'http://localhost:8080'
