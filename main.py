from flask import Flask, render_template, request, redirect
import random
import smtplib
import requests
import pymongo
import bcrypt
from flask_expects_json import expects_json
from flask_cors import CORS, cross_origin

schema = {
    'PositionType': 'string',
    'Lots': 'int',
    'LegStopLoss': {
        'Type': 'string',
        'Value': 'int'
    },
    'LegTarget': {
        'Type': 'string',
        'Value': 'int'
    },
    'LegTrailSL': {
        'Type': 'string',
        'Value': {
            'InstrumentMove': 'int',
            'StopLossMove': 'int'
        }
    },
    'LegMomentum': {
        'Type': 'string',
        'Value': 'int'
    },
    'ExpiryKind': 'string',
    'EntryType': 'string',
    'StrikeParameter': 'string',
    'InstrumentType': 'string',
    'LegReentrySL': {
        'Type': 'string',
        'Value': 0
    },
    'LegReentryTP': {
        'Type': 'string',
        'Value': 'int'
    }
}

app = Flask(__name__)
cors = CORS(app, resources={r"post": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["info"]
mycol2 = mydb['info2']

@app.route("/")
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html', msg='')

@app.route('/Login',methods=['POST'])
def Login():
    login_email = request.form['email']
    login_pass = request.form['password']
    login_pas = login_pass.encode('utf-8')
    login_info = mycol.find_one({'email': login_email})

    if login_info != None:
        if bcrypt.checkpw(login_pas, login_info['password']):
            return redirect('http://127.0.0.1:3000')
        else:
            return render_template('login.html', msg='Incorrect Password')
    else:
        return render_template('login.html', msg='User does not exist')


@app.route('/forget')
def forget():
    return render_template('forget.html', msg='')

@app.route('/Forget', methods=['POST'])
def Forget():
    forget_email = request.form['email']
    login_info = mycol.find_one({'email': forget_email})
    if login_info != None:
        global forget_email_otp
        forget_email_otp = random.randint(1000, 9999)
        email_msg = 'Your OTP is ' + str(forget_email_otp)
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        s.login("your email id", "password")
        s.sendmail('&&&&&&&&&&&', forget_email, email_msg)
        return render_template('verify_forgot_email.html')
    else:
        return render_template('forget.html', msg='User does not exist')

@app.route('/validate_forgot_email',methods=['POST'])
def validate_forgot_email():
    otp = request.form['otp']
    if int(otp) == forget_email_otp:
        return render_template('Homepage.html')
    else:
        return render_template('forget.html', msg='Invalid OTP')


@app.route('/signup')
def signup():
    return render_template('signup.html', msg='')

@app.route('/Signup', methods=['POST'])
def Signup():
    global email_otp, email, name, phone, password
    email = request.form['email']
    name = request.form['name']
    phone = request.form['phone']
    password = request.form['password']
    email_otp = random.randint(1000, 9999)
    email_msg = 'Your OTP is ' + str(email_otp)
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login("saini.ramneet21@gmail.com", "iuvojxffzjbfybvr")
    s.sendmail('&&&&&&&&&&&', email, email_msg)
    return render_template('verify_email.html')

@app.route('/validate_email', methods=['POST'])
def validate_email():
    return render_template('verify_phone.html')
    otp = request.form['otp']
    if int(otp) == email_otp:
        global phone_otp
        phone_otp = random.randint(1000, 9999)
        url = "2factorapi{}/{}".format(str(phone), str(phone_otp))
        payload = ""
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        requests.request("GET", url, data=payload, headers=headers)
        return render_template('verify_phone.html')
    else:
        return render_template('signup.html', msg='Not Verified!! Try Again')

@app.route('/validate_phone', methods=['POST'])
def validate_phone():

    otp = request.form['otp']
    if int(otp) == phone_otp:
        bytePwd = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(bytePwd, mySalt)
        data = {'name': str(name), 'email': str(email), 'phone': str(phone), 'password': pwd_hash}
        mycol.insert_one(data)
        return render_template('index.html')
    else:
        return render_template('signup.html', msg='Not Verified!! Try Again')

@app.route("/post", methods=['GET'])
@expects_json(schema)
@cross_origin(origin='*', headers=['Content-Type', 'Authorization'])
def backtest():
    request_data = request.get_json()
    positionType = request_data['PositionType']
    lots = request_data['Lots']
    legStopLoss = request_data['LegStopLoss']
    legTarget = request_data['LegTarget']
    legTrailSL = request_data['LegTrailSL']
    legMomentum = request_data['LegMomentum']
    expiryKind = request_data['ExpiryKind']
    entryType = request_data['EntryType']
    strikeParameter = request_data['StrikeParameter']
    instrumentType = request_data['InstrumentType']
    legReentrySL = request_data['LegReentrySL']
    legReentryTP = request_data['LegReentryTP']
    listInfo = {
        'email': email,
        'positionType': positionType,
        'lots': lots,
        'legStopLoss': legStopLoss,
        'legTarget': legTarget,
        'legTrailSL': legTrailSL,
        'legMomentum': legMomentum,
        'expiryKind': expiryKind,
        'entryType': entryType,
        'strikeParameter': strikeParameter,
        'instrumentType': instrumentType,
        'legReentrySL': legReentrySL,
        'legReentryTP': legReentryTP
    }
    mycol2.insert_one(listInfo)


if __name__ == '__main__':
    app.run(debug=True,port=5000)