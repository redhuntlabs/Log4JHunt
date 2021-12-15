# LogPew
An automated, reliable scanner for the Log4Shell CVE-2021-44228 vulnerability.

![image](https://user-images.githubusercontent.com/39941993/146184537-c6097017-1a95-445b-bede-c068912c7952.png)

### Usage
Here the help usage:
```js
$ python3 logpew.py --help

              L o g P e w

    A Log4Shell (CVE-2021-44228) Scanner

[-] You have to supply at least a single host to scan!
usage: logpew.py [-h] [-u URL] [-f FILE] [-d DELAY] [-t TIMEOUT] [-T TOKEN] [-E EMAIL] [-W WEBHOOK] [-S SERVER] [-ua USERAGENT] [-m METHOD] [-H HEADERS] [-p PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to probe for the vulnerability.
  -f FILE, --file FILE  Specify a file containing list of hosts to scan.
  -d DELAY, --delay DELAY
                        Delay in-between two concurrent requests.
  -t TIMEOUT, --timeout TIMEOUT
                        Scan timeout for a single host.
  -T TOKEN, --token TOKEN
                        Canary token to use in payloads for scanning.
  -E EMAIL, --email EMAIL
                        Email to receive notifications.
  -W WEBHOOK, --webhook WEBHOOK
                        Webhook URL to receive notifications.
  -S SERVER, --server SERVER
                        Custom DNS callback server for receiving notifications.
  -ua USERAGENT, --user-agent USERAGENT
                        Custom user agent string to use for requests.
  -m METHOD, --methods METHOD
                        Comma separated list of HTTP Method to use
  -H HEADERS, --headers HEADERS
                        Comma separated list of custom HTTP headers to use.
  -p PROXY, --proxy PROXY
                        HTTP proxy to use (if any).
```

#### Getting a token
The tool makes use of Log4Shell tokens from [Canary Tokens](https://canarytokens.org). The tool has capability to automatically generate tokens, if the values of the token (`--token`) and server (`--server`) are empty.

#### Targets specification
You can specify the targets in two modes:
- Scan a single URL:
  ```
  ./logpew.py -u 1.2.3.4:8080 ...
  ```
- Use a file to specify a list of targets:
  ```
  ./logpew.py -f targets.txt ...
  ```

#### Specifying notification channels
There are two ways in which you can receive notification channels:
- email (`--email`) -- service provided by Canarytokens.
- webhook (`--webhook`) -- service provided by Canarytokens.
- custom server (`--server`) -- you own custom DNS callback server.

Once the tool finds a vulnerable server, notifications would be relayed back to your preferred communication channel.

#### Sending requests
- You can customize the HTTP methods using `--methods`.
- A custom set of HTTP headers can be specified via `--headers` respectively.
- A custom user agent can be specified using `--user-agent` header.
- You can specfy a custom timeout value using `--timeout`.
- You can specify custom proxies to use in HTTP requests via `--proxy`.

#### Specifying delay

Since a lot of HTTP requests are involved, it might be a cumbersome job for the remote host to handle the requests. The `--delay` parameter is here to help you with those cases. You can specify a delay value in seconds -- which will be used be used in between two subsequent requests to the same port on a server.

### License & Version
The tool is licensed under the MIT license. See [LICENSE](LICENSE).

Currently the tool is at v0.1.

### Credits
The Research Team at [RedHunt Labs](https://redhuntlabs.com) would like to thank [Thinkst Canary](https://canary.tools) for the awesome [Canary Token](https://canarytokens.org) Project. 
