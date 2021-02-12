import requests
import random
import hashlib
import json
from datetime import datetime
import time
import getpass


def csrftoken_gen(length=32):
    character = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join((random.choice(character) for i in range(length)))


def encrypt_SHA256(password):
    sha_signature = \
        hashlib.sha256(
            (hashlib.md5(password.encode()).hexdigest()).encode()).hexdigest()
    return sha_signature


def createHeaders(csrftoken, cookies, referer='https://shopee.vn/buyer/login/'):
    headers = {
        'content-type': 'application/json',
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4407.0 Safari/537.36 Edg/90.0.789.1',
        'x-api-source': 'pc',
        'x-csrftoken': csrftoken,
        'x-requested-with': 'XMLHttpRequest',
        'x-shopee-language': 'vi',
        'referer': referer,
        'cookie': cookies,
    }
    return headers


def getInitCookies():
    headers = createHeaders(csrftoken, "csrftoken=" + csrftoken)
    response = session.request(
        'POST', 'https://shopee.vn/api/v2/authentication/get_active_login_page', headers=headers)
    cookie_string = "; ".join([str(x)+"="+str(y)
                               for x, y in response.cookies.get_dict().items()])
    cookie_string = "csrftoken=" + csrftoken + "; " + cookie_string
    return cookie_string


def loginShopee(cookie_string):
    headers = createHeaders(csrftoken, cookie_string)
    payload = {
        'username':   username,
        'password':   encrypt_SHA256(password),
        'support_whats_app':   True,
        'support_ivs':   True,
    }
    json_stringify = json.dumps(payload)
    url = "https://shopee.vn/api/v2/authentication/login"
    response = session.request(
        "POST", url, headers=headers, data=json_stringify)
    return response.content


def inputOTP(cookie_string):
    vcode = input("Nhap ma OTP:")
    payload = {
        'username':   username,
        'otp':   vcode,
        'support_ivs':   True,
    }
    json_stringify = json.dumps(payload)
    headers = createHeaders(csrftoken, cookie_string)
    url = "https://shopee.vn/api/v2/authentication/vcode_login"
    response = session.request(
        "POST", url, headers=headers, data=json_stringify)
    return response.content


def checkLoginSuccess():
    res = session.request(
        "GET", "https://mall.shopee.vn/api/v2/user/login_status")
    return res


def getFeeds(t, limit, feed_session_id, rcmd_session_id=None, last_feed_id=None):
    if last_feed_id != None:
        url = 'https://feeds.shopee.vn/api/proxy/timeline/home?t=' + t
        url += '&limit=' + limit + '&feed_session_id=' + \
            feed_session_id + '&rcmd_session_id=' + rcmd_session_id
        url += '&last_feed_id=' + last_feed_id
    else:
        url = 'https://feeds.shopee.vn/api/proxy/timeline/home?t=' + \
            t + '&limit=' + limit + '&feed_session_id=' + feed_session_id
    res = session.request("GET", url)
    return res.json()


def likeFeed(feed, cookie_string):
    global cs
    url = 'https://feeds.shopee.vn/api/proxy/like'
    headers = createHeaders(csrftoken, cookie_string,
                            'https://feeds.shopee.vn/')
    payload = {
        'feed_id': feed['feed_id'],
    }
    json_stringify = json.dumps(payload)
    response = session.request(
        "POST", url, headers=headers, data=json_stringify)
    data = response.json()
    if data['code'] == 0:
        cs = cs + 1
    return data['msg'] + f"({cs})"


session = requests.Session()
csrftoken = csrftoken_gen()
cs = 0
username = input("Input username:")
password = getpass.getpass(prompt='Input password:')


def main():
    cookie_string = getInitCookies()
    loginShopee(cookie_string)
    inputOTP(cookie_string)
    res_islogin = checkLoginSuccess()
    print(res_islogin.content)
    new_cookie = "; ".join([str(x)+"="+str(y)
                            for x, y in res_islogin.cookies.get_dict().items()])
    cookie_string = "csrftoken=" + csrftoken + "; " + new_cookie
    timestamp = str(int(datetime.timestamp(datetime.now()) * 1000))
    limit = '20'
    feed_session_id = str(int(datetime.timestamp(
        datetime.now()) * 1000)) + '_' + csrftoken_gen(40)
    rcmd_session_id = None
    last_feed_id = None
    has_more = True
    while has_more:
        data = getFeeds(timestamp, limit, feed_session_id,
                        rcmd_session_id, last_feed_id)
        feeds = data['data']['list']
        for feed in feeds:
            if feed['content']['is_like'] == False:
                print(likeFeed(feed, cookie_string))
                time.sleep(6)
        rcmd_session_id = str(data['data']['rcmd_session_id'])
        last_feed_id = str(feed['feed_id'])
        feed = None
        has_more = data['data']['has_more']


def run(rf):
    if rf != 0:
        print('Fail '+ str(rf) + ' times')
    if rf == 50:
        return
    try:
        main()
    except:
        rf = rf + 1
        run(rf)


if __name__ == '__main__':
    run(0)