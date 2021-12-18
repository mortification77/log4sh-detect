# log4sh-detect

log4sh-detect is a MULTI-PLATFORM Python Script that will detect hosts vulnerable to the log4shell Exploit.

It has been tested on Windows and Linux (CentOS).

**NOTE** that this script tests HTTP(S) ONLY, but other services that use log4j may be vulnerable.

## Installation

There is no installation.  Simply copy the script to a Test Host that will be used to check for vulnerable servers.

You MAY need to install any missing Python Modules -- MOST are STANDARD, but some, such as "requests" may need to be installed using pip.

```
pip install requests
```

## Operation

The scipt does the following:

1) HTTP Test:

* Send the SAME HTTP Request to the target WITHOUT the exploit to validate that connectivity to the host exists. [CAN BE DISABLED, but HIGHLY RECOMMENDED NOT TO!]

* If this test fails to send, the script stops here with TEST_FAILED.

2. Begin a Raw TCP Listener Thread to listen for LDAP Requests (a Callback) from the host being tested.

* The script ONLY responds back to an initial "LDAP Bind Request" with "LDAP Bind Success", causing the next request from a vulnerable server to send the "Random User Data String" back to us.


3. Test the "Callback Path":

* Connects to itself via the specified "Callback IP" as a public NAT can be used to test hosts behind a router / firewall. [CAN BE DISABLED, but HIGHLY RECOMMENDED NOT TO!]

4. Send the Exploit Request:

* If this request fails to send *AND* the HTTP Test from #1 SUCCEEDS (and was NOT DISABLED), the script stops here, indicating that the host being tested is PATCHED.

* If this request fails to send *AND* the HTTP Test was NOT ENABLED, it stops here, indicating TEST_FAILED.

5. Wait for 10 seconds for a response from a vulnerable host.

* If a request is received, the host is VULNERABLE, otherwise not_vulnerable.


## Usage
```
Usage: log4sh-detect.py [-erTWx] [--skip-http-test] [-i|p|h|t <arg>] <url>

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

```

## Examples

### Check host with details
```
# ./log4sh-detect.py -p 1389 localhost:8080
```
```
# python3 log4sh-detect.py -p 1389 localhost:8080
2021-12-14 13:22:13 Local Callback Listener Opened
port                           1389

2021-12-14 13:22:13 Validating Callback IP / Port reachability...

2021-12-14 13:22:13 Callback IP / Port reachability Test
exploitCBIP                    192.168.0.20
exploitCBPort                  1389
status                         SUCCEEDED

2021-12-14 13:22:13 Sending Exploit HTTP Request
url                            localhost:8080

2021-12-14 13:22:13 Exploit HTTP Request Sent
url                            localhost:8080
succeeded                      True
http_status                    200

2021-12-14 13:22:13 Wait for Exploited Host Callback
callbackIP                     192.168.0.20
callbackPort                   1389
callbackTimeout                10.0

localhost:8080                           [VULNERABLE]
```

### Check host WITHOUT details (result only)
```
# python3 log4sh-detect.py -r -p 1389 localhost:8080
```
```
localhost:8080                           [VULNERABLE]
```

## NOTES:

### Callback IP / Port
To scan an Internet-Facing Host from a host behind a router, you will be *REQUIRED TO*:

1. Map the *PUBLIC* Callback IP / Port to the *PRIVATE* Callback IP / Port used on the host running this script.
2. Pass the *PUBLIC* Callback IP / Port to the script using the "-i `<ip`>" and "-p `<port`>" options.
* The script performs a check to validate that the Callback IP / Port can be contacted, but it is *NOT* guaranteed to be 100% accurate as the network path back to the script may not be exactly the same.


## Contributing
Pull requests are NOT welcome (AT THIS TIME).

Please open an issue first to discuss what you would like to change.


## License
Standard MIT License:
[MIT](https://choosealicense.com/licenses/mit/)