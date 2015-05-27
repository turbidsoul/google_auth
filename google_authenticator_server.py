#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Administrator
# @Date:   2014-12-25 22:33:12
# @Last Modified 2015-05-27
# @Last Modified time: 2015-05-27 23:02:27


import base64
import dbm
import hashlib
import hmac
import struct
from math import floor
from random import randint
from time import time

import qrcode as qr
from beaker.middleware import SessionMiddleware
from bottle import get, post, request, response, run, view, app

base32_table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', '2', '3', '4', '5', '6', '7',
]


session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 3600,
    'session.data_dir': './data',
    'session.auto': True
}
app = SessionMiddleware(app(), session_opts)

def create_secret(secretlen=16):
    return ''.join([base32_table[randint(0, len(base32_table)-1)] for i in range(0,secretlen)])


def get_code(secret, time_slice=None):
    if not time_slice:
        time_slice = floor(time() / 30)
    secret = secret.upper()
    msg = struct.pack('>Q', time_slice)
    key = base64.b32decode(secret, True)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(chr(h[19])) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


@get('/qrcode')
def qrcode():
    params = request.params
    author = params['author']
    email = params['email']
    db = dbm.open('db', 'c')
    if author in db:
        secret = db[author].decode().split(';,')[1]
    else:
        secret = create_secret()
    print(secret)
    db[author] = '%s;,%s' % (email, secret)
    db.close()
    session = request.environ.get('beaker.session')
    session['author'] = author
    secretstr = 'otpauth://%s/%s:%s?secret=%s&issuer=%s' % ('totp', author, email, secret, author)
    gaqr = qr.make(secretstr)
    imgname = '%s[%s]@%s.png' % (author, email, secret)
    gaqr.save(imgname)
    response.content_type = 'image/png'
    qrimg = None
    with open(imgname, 'rb') as f:
        qrimg = f.read()
    return qrimg


@get('')
@get('/')
@view('index')
def index():
    return {}


@post('/verify')
def verify():
    code = request.params['code']
    session = request.environ.get('beaker.session')
    author = session.get('author')
    db = dbm.open('db', 'c')
    secret = db[author].decode().split(';,')[1]
    print(secret)
    db.close()
    server_code = str(get_code(secret))
    print(server_code, code)
    if server_code == code:
        return "SUCCESS"
    else:
        return "FAILURE"



if __name__ == '__main__':
    run(app=app, host='127.0.0.1', port=8080, reloader=True)
    # code = get_code('TUPQULFJ2UEKUPCS')
    # print(code)
