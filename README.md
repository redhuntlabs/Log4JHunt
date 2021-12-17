# Log4JHunt
An automated, reliable scanner for the Log4Shell CVE-2021-44228 vulnerability.

https://user-images.githubusercontent.com/39941993/146377497-a821f222-e292-4de7-8596-bded155dc787.mp4

### Usage
Here the help usage:
```js
$ python3 log4jhunt.py

          +--------------+
              Log4JHunt
          +--------------+

[+] Log4jHunt by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[+] Author: Pinaki Mondal (RHL Research Team)
[+] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.

[-] You have to supply at least a single host to scan!

usage: log4jhunt.py [-h] [-u URL] [-f FILE] [-d DELAY] [-t TIMEOUT] [-T TOKEN] [-E EMAIL] [-W WEBHOOK] [-S SERVER] [-ua USERAGENT] [-m METHOD] [-H HEADERS] [-p PROXY]

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

Once the token is generated, the token and the auth value are written to a file called `canary-token.json`.

#### Targets specification
You can specify the targets in two modes:
- Scan a single URL:
  ```
  ./log4jhunt.py -u 1.2.3.4:8080 ...
  ```
- Use a file to specify a list of targets:
  ```
  ./log4jhunt.py -f targets.txt ...
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

#### More details around the Log4J
We have covered more details around Log4j Vulnerability in our [Blog](https://redhuntlabs.com/blog/log4j-vulnerability-things-you-should-know.html).

### License & Version
The tool is licensed under the MIT license. See [LICENSE](LICENSE).

Currently the tool is at v0.1.

### Credits
The Research Team at [RedHunt Labs](https://redhuntlabs.com) would like to thank [Thinkst Canary](https://canary.tools) for the awesome [Canary Token](https://canarytokens.org) Project.

(To know more about our Attack Surface Management platform #ASM, check out NVADR)[https://redhuntlabs.com/nvadr].
