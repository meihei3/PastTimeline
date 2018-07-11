# -*- coding: utf-8 -*-

import json
from collections import Counter
from datetime import datetime, timedelta
import os
# type hint
from typing import List, Tuple

# oauth認証
import oauth2
from requests_oauthlib import OAuth1
# twitter request
import requests
# flask
from flask import Flask, request, render_template, session, redirect
# page caching
# 余裕ができたら使う
from werkzeug.contrib.cache import SimpleCache

app = Flask(__name__)
app.config['SECRET_KEY'] = 'The secret key which ciphers the cookie'

CK = os.environ["TWITTER_CONSUMER_KEY"]  # Consumer Key
CS = os.environ["TWITTER_CONSUMER_SECRET"]  # Consumer Secret

SEARCH_URL = "https://api.twitter.com/1.1/search/tweets.json"
TIMELINE_URL = "https://api.twitter.com/1.1/statuses/home_timeline.json"
ACCESS_URL = "https://api.twitter.com/oauth/access_token"
REQUEST_URL = "https://api.twitter.com/oauth/request_token"
OAUTH_URL = "https://twitter.com/oauth/authorize"
ACCOUNT_URL = "https://api.twitter.com/1.1/account/verify_credentials.json"


def get_request_token_keys():
    consumer = oauth2.Consumer(key=CK, secret=CS)
    client = oauth2.Client(consumer)
    resp, content = client.request("https://api.twitter.com/oauth/request_token", "GET")
    return {k: v for k, v in [st.split('=') for st in content.decode('utf-8').split('&')]}


def get_authorize_url(request_token: str):
    return OAUTH_URL + "?oauth_token=" + request_token


def get_access_token_keys(oauth_token: str, oauth_verifier: str):
    consumer = oauth2.Consumer(key=CK, secret=CS)
    token = oauth2.Token(oauth_token, oauth_verifier)
    client = oauth2.Client(consumer, token)
    resp, content = client.request("https://api.twitter.com/oauth/access_token",
                                   "POST", body="oauth_verifier={0}".format(oauth_verifier))
    return {k: v for k, v in [st.split('=') for st in content.decode('utf-8').split('&')]}


def get_user_screen_name(status):
    return status["user"]["screen_name"]


def get_timeline_common_user_list(timeline):
    if 'errors' in timeline:
        raise RuntimeError()
    names = [get_user_screen_name(status) for status in timeline]
    return Counter(names).most_common()


def create_query(day: int, common_user_list: List[Tuple[str, int]]):
    dt = (datetime.now() - timedelta(days=day)).strftime('%Y-%m-%d_%H:%M:%S_JST')
    query = "until:%s -filter:replies" % dt
    users_query = ""
    for user, i in common_user_list:
        pre = users_query
        if users_query == "":
            users_query = "from:%s " % user
        else:
            users_query += "OR from:%s " % user
        if len(users_query + query) > 500:
            users_query = pre
            break
    return users_query + query


def get_home_timeline(auth, cnt: int = 200):
    assert 1 <= cnt <= 200
    params = {"count": cnt}
    r = requests.get(TIMELINE_URL, auth=auth, params=params)
    return json.loads(r.text)


def get_searched_tweet(auth, query: str, cnt: int = 50):
    assert 1 <= cnt <= 100
    params = {"q": query, "count": cnt}
    r = requests.get(SEARCH_URL, auth=auth, params=params)
    return json.loads(r.text)["statuses"]


def get_past_timeline(auth, day: int):
    try:
        tl = get_home_timeline(auth)
        query = create_query(day=day, common_user_list=get_timeline_common_user_list(tl))
        return get_searched_tweet(auth, query)
    except RuntimeError:
        return [{"error": {"code": "88", "message": "APIリクエストが上限に達しました"}}]


def get_user_profile(auth):
    return json.loads(requests.get(ACCOUNT_URL, auth=auth).text)


def check_error(res):
    if res.status_code == 200:
        pass
    raise ValueError()


# jinja2用の関数
def to_JST(dtstr: str):
    dt = datetime.strptime(dtstr, '%a %b %d %H:%M:%S +0000 %Y') + timedelta(hours=9)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


app.jinja_env.globals.update(to_JST=to_JST)


# 各 route() 関数の前に実行される処理
@app.before_request
def before_request():
    # セッションが保存されている (= ログイン済み)
    if session.get('oauth_token') is not None and session.get('oauth_token_secret') is not None:
        return
    # リクエストがログインに関するもの
    if request.path in ('/login', '/callback', '/cache'):
        return
    # ログインされておらずログインページに関するリクエストでもなければリダイレクトする
    return redirect('/login')


@app.route('/')
def index():
    days = request.args.get('days')
    oauth_token = session.get("oauth_token")
    oauth_verifier = session.get("oauth_token_secret")
    if days is None:
        return redirect('/select')
    auth = OAuth1(CK, CS, oauth_token, oauth_verifier)
    tweets = get_past_timeline(auth, day=int(days))
    profile = get_user_profile(auth)
    return render_template("index.html", data=tweets, profile=profile)


@app.route('/callback')
def callback():
    oauth_token = request.args.get("oauth_token")
    oauth_verifier = request.args.get("oauth_verifier")
    access_keys = get_access_token_keys(oauth_token, oauth_verifier)
    session['oauth_token'] = access_keys["oauth_token"]
    session['oauth_token_secret'] = access_keys["oauth_token_secret"]
    return redirect('/')


@app.route('/login')
def login():
    return render_template('login.html',
                           link=get_authorize_url(get_request_token_keys()["oauth_token"]))


@app.route('/logout')
def logout():
    session.pop("oauth_token", None)
    session.pop("oauth_token_secret", None)
    return redirect('/')


@app.route('/select')
def select():
    return render_template('select.html')


if __name__ == '__main__':
    app.debug = True
    app.run()
