![GitHub](https://img.shields.io/github/license/rhydian76/IISLogParser)

# IISLogFileParser
A basic Python3 parser tool for IIS Logs which summarises findings from the log file.

Inspired by the Gist https://gist.github.com/wh13371/e735bc865a494c35513e 


## Usage

``iislogparse.py [-h] -f <iis logfile> [-c] [-t <number>] [-p <number>] [-x <x.x.x.x,y.y.y.y] [-b] [-d] [-r]``

Switches:
```
-h                  Display this help message
-f <filename>       Path to the IIS log file to analyse
-c                  Display a breakdown of HTTP status codes
-t <number>         Display the top <number> clients. Defaults to 10 if ommitted
-p <number>         Display the top <number> most requested pages. Defaults to 10 if ommitted
-x <ip,ip>          A comma separated list of IP addresses to exclude from the report. No spaces allowed
-b                  Display a breakdown of total requests per hour
-d                  Display a breakdown of total requests per date
-r                  Attempt reverse DNS lookup of top client IP addresses (May slow reporting)
```
