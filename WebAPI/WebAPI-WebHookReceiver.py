#!/usr/bin/python
from flask import Flask, request
from modules.ScanModule import *


app = Flask(__name__)

@app.route('/vulncheck', methods=['POST'])
def api():
    if request.method == 'POST':
        #check user details from db
        pass

    else:
        #serve login page
        pass