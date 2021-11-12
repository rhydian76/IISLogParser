## IISLogFileParser

A basic parser tool for IIS Logs which summarises findings from the log file.

Inspired by the Gist https://gist.github.com/wh13371/e735bc865a494c35513e 


# Usage

``iislogparse.py [-h] -f <iis logfile> [-s] [-c] [-t <number>] [-x <x.x.x.x,y.y.y.y] [-b] [-d]``

Switches:
```
-h                  Display this help message.
-f <filename>       Path to the IIS log file to analyse.
-s                  Summarise only. Do not display each request.
-c                  Display a breakdown of HTTP status codes.
-t <number>         Display the top <number> clients. Defaults to 10 if ommitted.
-x <ip,ip>          A comma separated list of IP addresses to exclude from the report. No spaces allowed.
-b                  Display a breakdown of total requests per hour.
-d                  Display a breakdown of total requests per date.
```
