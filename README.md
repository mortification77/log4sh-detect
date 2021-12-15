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

## Usage
```
Usage: log4sh-detect.py [-erT] [-i|p|h|t <arg>] <url>

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