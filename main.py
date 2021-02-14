import requests,pickle
import random
import hashlib
import json
from datetime import datetime
import time
import getpass
import os


def csrftoken_gen(length=32):
    character = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join((random.choice(character) for i in range(length)))


def encrypt_SHA256(password):
    sha_signature = \
        hashlib.sha256(
            (hashlib.md5(password.encode()).hexdigest()).encode()).hexdigest()
    return sha_signature


def save_cookies(filename,cookies,is_str = True):
    # os.path.dirname(__file__)
    if is_str:
        with open(os.path.dirname(__file__) + '\\' + cookie_str_fn,'w') as file: 
            file.write(cookies)
    else:
        with open(os.path.dirname(__file__) + '\\' + cookie_ses_fn,'wb') as file: 
            pickle.dump(cookies, file)

def load_cookies(is_str = True):
    try:
        global csrftoken
        # os.path.dirname(__file__)
        if is_str:
            with open(os.path.dirname(__file__) + '\\' + cookie_str_fn,'r') as file:
                csrftoken_old = file.readline().replace('\n','')
                cookies_str = file.readline()
                if(csrftoken_old != '' and len(csrftoken_old) == 32):
                    csrftoken = csrftoken_old
                    return cookies_str
        else:
            with open(os.path.dirname(__file__) + '\\' + cookie_ses_fn,'rb') as file:
                if file != '':
                    # load cookies and do a request
                    # requests.get(  url, cookies=load_cookies(filename))
                    return pickle.load(file)
        return ''
    except Exception as e:
        print(e)
        return ''
        

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
    global has_cookie
    cookie_string = ''
    cookie_ses    = ''
    # lấy cookie củ (nếu có)
    cookie_string_old = load_cookies()
    if cookie_string_old != '':
        cookie_string = cookie_string_old
    else:
        has_cookie = False
    
    cookie_ses = load_cookies(False)
    if cookie_ses != '':
        session.cookies.update(cookie_ses)
    else:
        has_cookie = False
    # Nếu có cookie củ thì dùng
    if has_cookie:
        return cookie_string
    # Không có thì lấy cookie mới
    headers = createHeaders(csrftoken, "csrftoken=" + csrftoken)
    response = session.request(
        'POST', 'https://shopee.vn/api/v2/authentication/get_active_login_page', headers=headers, cookies=load_cookies(False))
    cookie_string = "; ".join([str(x)+"="+str(y)
                            for x, y in response.cookies.get_dict().items()])
    cookie_string = "csrftoken=" + csrftoken + "; " + cookie_string
    save_cookies(cookie_str_fn,csrftoken + '\n' + cookie_string)
    save_cookies(cookie_ses_fn,session.cookies,False)
    return cookie_string


def loginShopee(cookie_string):
    global username
    global password
    # Nhập username
    username = input("Nhập tài khoản:")
    # Nhập password
    password = getpass.getpass(prompt='Nhập mật khẩu:')
    headers  = createHeaders(csrftoken, cookie_string)
    payload  = {
        'username':   username,
        'password':   encrypt_SHA256(password),
        'support_whats_app':   True,
        'support_ivs':   True,
    }
    json_stringify = json.dumps(payload)
    url = "https://shopee.vn/api/v2/authentication/login"
    response = session.request(
        "POST", url, headers=headers, data=json_stringify)
    data = response.json()
    
    if data['error'] == 0:
        return data
    elif data['error'] == 35:
        print('Mã xác minh của bạn sẽ được gửi bằng tin nhắn đến điện thoại của bạn.')
        inputOTP(cookie_string)
    else:
        print('Đăng nhập KHÔNG thành công. Bạn vui lòng thử lại hoặc đăng nhập bằng cách khác nhé!')
        loginShopee(cookie_string)
    return data


def inputOTP(cookie_string):
    vcode = input("Nhap ma OTP:")
    payload = {
        'username'   :   username,
        'otp'        :   vcode,
        'support_ivs':   True,
    }
    json_stringify  = json.dumps(payload)
    headers         = createHeaders(csrftoken, cookie_string)
    url             = "https://shopee.vn/api/v2/authentication/vcode_login"
    response        = session.request(
        "POST", url, headers=headers, data=json_stringify)
    data            = response.json()
    if data['error'] != None:
        print('Mã xác nhận không đúng, bạn vui lòng đăng nhập lại.')
        loginShopee(cookie_string)
    return data


def getCookieShopeeMall():
    global has_cookie
    global username
    res = session.request(
        "GET", "https://mall.shopee.vn/api/v2/user/login_status")
    data = res.json()
    print(data)
    # Nếu khong lay duọc data thì cookie dang sai
    if data['error'] != 0:
        # lấy lại cookie
        has_cookie = False
        return ''
    if has_cookie:
        print(f'Bạn đang đăng nhập tài khoản [{data["data"]["username"]}]')
        new_account = input('Bạn có muốn đăng nhập tài khoản khác? [Y/N]:')
        if str.lower(new_account) == 'y':
            has_cookie = False
            return ''
    new_cookie = "; ".join([str(x)+"="+str(y)
                            for x, y in res.cookies.get_dict().items()])
    return "csrftoken=" + csrftoken + "; " + new_cookie


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
    print(data['msg'] + f"({cs})")
    return data


session = requests.Session()
csrftoken = csrftoken_gen()
last_like_feed = 0
# Xem co ton tai cookie chưa
has_cookie = True
# tên file chưa cookie
cookie_str_fn = 'cookies_str.txt'
cookie_ses_fn = 'cookies_ses.txt'
# số lượt chạy thất bại
rf = 0
# biến đến số lượt thành công
cs = 0
# username
username = ''
# password
password = ''

def feed_main(cookie_string):
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
                setTimeSleep()
                likeFeed(feed, cookie_string)
            if feed['header']['info']['is_follow'] == False:
                followShop(cookie_string,feed['header']['info']['shop_id'])
        rcmd_session_id = str(data['data']['rcmd_session_id'])
        last_feed_id = str(feed['feed_id'])
        feed = None
        has_more = data['data']['has_more']


def followShop(cookie_string,shopid):
    url = "https://shopee.vn/api/v4/shop/follow"
    headers = createHeaders(csrftoken,cookie_string,'https://shopee.vn/shop/' + str(shopid))
    # payload = {
    #     'shopid': int(shopid),
    # }
    # json_stringify = json.dumps(payload)
    json_stringify = '{"shopid": '+ str(shopid) +'}'
    response = session.request(
        "POST", url, headers=headers, data=json_stringify)
    data = response.json()
    if data['error'] == 0:
        print('Followed shopid ' + shopid)
    return data


def setTimeSleep():
    global last_like_feed
    if datetime.timestamp(datetime.now()) - last_like_feed < 6:
        time.sleep(6 - (datetime.timestamp(datetime.now()) - last_like_feed))
    last_like_feed = datetime.timestamp(datetime.now())

def main():
    # khơit tạo cookie
    cookie_string = getInitCookies()
    if has_cookie != True:
        loginShopee(cookie_string)
    cookie_string = getCookieShopeeMall()
    if cookie_string == '':
        global session
        # session = requests.Session()
        main()
    
    save_cookies(cookie_str_fn,csrftoken + '\n' + cookie_string)
    save_cookies(cookie_ses_fn,session.cookies,False)
    run(cookie_string)


def run(cookie_string):
    global rf
    if rf != 0:
        print('Fail '+ str(rf) + ' times')
    if rf == 50:
        return
    try:
        feed_main(cookie_string)
    except Exception as e:
        print(e)
        rf = rf + 1
        try:
            cookie_string_new = getCookieShopeeMall()
            if cookie_string_new == '':
                main()
            cookie_string = cookie_string_new
        except Exception as ee:
            print(ee)
        run(cookie_string)


if __name__ == '__main__':
    main()
    
