'''
Created on Feb 20, 2015

@author: banna
'''
import requests
import hashlib
import base64
import socket
import sys
from thread import *
import logging
from boto.sns import connect_to_region
import re

############# Logger ###################
logging.basicConfig(filename='mobill.log',
    filemode='a',
    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    level=logging.DEBUG
)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)
################ Logger #################

HOST                = ''   # Symbolic name meaning all available interfaces
PORT                = 8888 # Arbitrary non-privileged port
################ Mobill params ##########
mobillHostURI       = "acc.mobill.se"
clientId            = "17378838-b064-11e4-ab7d-12e3f512a338"
messageType         = "APP_SESSION_REQUEST"
messageService      = "APP"
orderCode           = "T1A"
companyDivisionCode = "DXB"
orderChannelName    = "APP"
sharedSecret        = "PA3WSQW21P"
imei                = "1234"
mcpVersion          = "2.1"
mobillValidatorPort = 8093
regPlate            = "true"
partialMCode        = "false"

CAMERA_ENTRY = "in"
CAMERA_EXIT = "out"


def startParkingSession(registrationNumber):
    request = {
        "clientId": clientId,
        "messageService": messageService,
        "messageType": messageType,
        "synchronous": "true"
    }

    message = {
        "companyDivisionCode": companyDivisionCode,
        "orderCode": orderCode,
        "orderChannelName": orderChannelName,
        "registrationNumber": registrationNumber,
        "session": "START"
    }

    hashString = "clientId:{0}!message:{1}!{2}".format(
                request["clientId"],
                str(message).replace("\'", "\""),
                sharedSecret
            ).replace(" ", "")

    logging.info("Hash string before encoding: " + hashString)

    request["hash"] = base64.b64encode(hashlib.sha1(hashString).digest())

    logging.info("Hash after encoding: " + request["hash"])

    request["message"] = str(message).replace("'", "\\'")

    requestString = str(request).replace('\'true\'', 'true').replace('\\\\', '\\').replace(" ", "").replace("\'", "\"")

    logging.info("Request: " + requestString)

    r = requests.post("http://" + mobillHostURI + "/mspRequest", data=requestString)

    logging.info("response: status: " + str(r.status_code))
    logging.info("response: header: " + str(r.headers))
    logging.info("response: body: " + str(r.text))

def validate(mCode):
    # login
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((mobillHostURI, mobillValidatorPort))

    command = str(bytearray.fromhex("02")) + str(bytearray.fromhex("06")) + imei + ";" + mcpVersion + ";MCPLib 2.0" + str(bytearray.fromhex("03"))

    logging.info(command)

    s.sendall(command)

    data = s.recv(2048)

    if data:
        logging.info("Validation server response: " + data)

    # validate
    validationData = {
        "deviceId": imei,
        "mCode": mCode,
        "partialMCode": partialMCode,
        "regPlate": regPlate
    }

    formattedData = str(validationData).replace("\'", "\"").replace("\"false\"", "false").replace("\"true\"", "true").replace(" ", "")

    command = str(bytearray.fromhex("02")) + str(bytearray.fromhex("08")) + formattedData + str(bytearray.fromhex("03"))

    logging.info(command)

    s.sendall(command)

    data = s.recv(2048)

    if data:
        logging.info("Validation server response: " + data)
        code = int(re.search("\d\d", data.replace(" ", "")).group(0))
        valid = True if code == 20 else False
        sendDataToCamera(valid, mCode)

    # acknowledge
    ackData = "{\"preProcMs\": 2587432319, \"ocrMs\": 1587432319, \"validationMs\": 3587432319}"

    ackCommand = str(bytearray.fromhex("02")) + str(bytearray.fromhex("10")) + ackData + str(bytearray.fromhex("03"))

    s.sendall(ackCommand)

    s.close()

def sendDataToCamera(validPlate, plate):
    # sending to data camera emulator (android app)
    logging.info("Valid plate? {0}".format(validPlate))
    sns = connect_to_region("us-west-2")

    hash = {
        "valid": 1 if validPlate else 0,
        "plate": plate
    }

    sns.publish(topic=u'arn:aws:sns:us-west-2:408341129482:PushDemoTopic', message=str(hash), subject='plate validation')

def recieveDataFromCamera(conn):
    data = conn.recv(1024)

    registrationNumber = data.split(":")[0]
    actionID = data.split(":")[1]

    logging.info("Recieved plate#: " + registrationNumber)
    logging.info("From OCR camera: " + actionID)

    if actionID == CAMERA_ENTRY:
        logging.info("Starting parking session for plate# " + registrationNumber)
        startParkingSession(registrationNumber)
    elif actionID == CAMERA_EXIT:
        logging.info("Validating plate# " + registrationNumber)
        validate(registrationNumber)
    else:
        logging.info("Unknown action")

def startServer():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'Socket created'


    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    print 'Socket bind complete'

    s.listen(10)
    print 'Waiting for plate number...'

    while 1:
        conn, addr = s.accept()
        print 'Connected with ' + addr[0] + ':' + str(addr[1])
        start_new_thread(recieveDataFromCamera, (conn,))

    s.close()

startServer()
