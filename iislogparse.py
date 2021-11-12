import fileinput, sys, getopt
from collections import Counter

def filterLogs(key, key_values, list_of_dicts):
 return list(filter(lambda d: d[key] not in key_values, list_of_dicts))

def displayHelp():
    print('\nUsage:')
    print('iislogparse.py [-h] -f <iis logfile> [-s] [-c] [-t <number>] [-x <x.x.x.x,y.y.y.y] [-b] [-d]')
    print('\nSwitches:')
    print('{:<20s}{:>6s}'.format('-h', 'Display this help message.'))
    print('{:<20s}{:>6s}'.format('-f <filename>', 'Path to the IIS log file to analyse.'))
    print('{:<20s}{:>6s}'.format('-s', 'Summarise only. Do not display each request.'))
    print('{:<20s}{:>6s}'.format('-c', 'Display a breakdown of HTTP status codes.'))
    print('{:<20s}{:>6s}'.format('-t <number>', 'Display the top <number> clients. Defaults to 10 if ommitted.'))
    print('{:<20s}{:>6s}'.format('-x <ip,ip>', 'A comma separated list of IP addresses to exclude from the report. No spaces allowed.'))
    print('{:<20s}{:>6s}'.format('-b', 'Display a breakdown of total requests per hour.'))
    print('{:<20s}{:>6s}'.format('-d', 'Display a breakdown of total requests per date.'))


def main(argv):
    l = [] # a list to hold a <dict> for each line in the IIS log file
    uniqueIPs = []
    allIPs = []
    header = []
    statusCodes = []
    hourlyRequests = []
    dailyRequests = []
    excludeList = []
    summariseOnly = False
    summariseHTTPCodes = False
    summariseByTime = False
    summariseByDate = False
    displayTop = 10

    try:
      opts, args = getopt.getopt(argv,"hscbdf:t:x:")
    except getopt.GetoptError:
      displayHelp()
      sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            displayHelp()
            sys.exit()
        if opt == '-f':
            iisLogfile = arg
        if opt == '-s':
            summariseOnly = True
        if opt == '-c':
            summariseHTTPCodes = True
        if opt == '-b':
            summariseByTime = True
        if opt == '-d':
            summariseByDate = True
        if opt == '-t':
            displayTop = int(arg)
        if opt == '-x':
            excludeList = arg.split(",")

    ## Read log format header format from the IIS log
    for line in fileinput.input(iisLogfile):
        if line.startswith('#Fields:'):
            header = line.split()

    ## Remove title field:
    header.pop(0)

    for line in fileinput.input(iisLogfile):
        if not line.startswith('#'):
            fields = line.split()
            d = dict(zip(header, fields)) # create a <dict> based on <headers> & <split> log lines
            l.append(d)
    
    filter_key = 'c-ip'

    filteredLogPayload = filterLogs(filter_key, excludeList, l)

    for logEntry in filteredLogPayload:
        if not summariseOnly:
            # Todo: check fields exist before printing
            print (logEntry.get('date'), logEntry.get('time'), logEntry.get('s-ip'), logEntry.get('s-port'), logEntry.get('c-ip'), logEntry.get('cs-method'), logEntry.get('cs-uri-stem'), logEntry.get('sc-substatus'))

        allIPs.append(logEntry.get('c-ip'))

        if summariseHTTPCodes:
            statusCodes.append(logEntry.get('sc-status'))
        
        if summariseByTime:
            logEntry.get('time')[:logEntry.get('time').index(":")]
            hourlyRequests.append(logEntry.get('time')[:logEntry.get('time').index(":")])

        if summariseByDate:
            dailyRequests.append(logEntry.get('date'))

        if logEntry.get('c-ip') not in uniqueIPs:
            uniqueIPs.append(logEntry.get('c-ip'))

    print('-' * 40)
    print('Analysis of IIS Log file', iisLogfile)
    print('-' * 40)
    print('{:<30s}{:>6s}'.format('Total records in log file: ', str(len(filteredLogPayload))))
    print('{:<30s}{:>6s}'.format('Total Unique Client IPs:',str(len(uniqueIPs))))
    if not summariseOnly:
        print('{:<30s}{:>6s}'.format('Unique Client IPs:'))
        for ip in uniqueIPs:
            print(ip)

    if summariseHTTPCodes:
        print('\nHTTP Status Code Breakdown:\n')
        print('{:<20s}{:>6s}'.format('Status Code','Occurrences'))
        print('{:<20s}{:>6s}'.format('-----------','-----------'))
        codeDict = dict(Counter(statusCodes))
        for count in (sorted(codeDict.items(), reverse=True, key=lambda item: item[1])):
            print('{:<20s}{:>6s}'.format(count[0], str(count[1])))
    
    if summariseByTime:
        print('\nRequest Breakdown by Hour:\n')
        print('{:<15s}{:>6s}'.format('Hour','Requests'))
        print('{:<15s}{:>6s}'.format('----','--------'))
        timeDict = dict(Counter(hourlyRequests))
        for count in (sorted(timeDict.items(), reverse=False, key=lambda item: item[0])):
            print('{:<15s}{:>6s}'.format(count[0], str(count[1])))

    if summariseByDate:
        print('\nRequest Breakdown by Date:\n')
        print('{:<20s}{:>6s}'.format('Date','Requests'))
        print('{:<20s}{:>6s}'.format('----','--------'))
        dateDict = dict(Counter(dailyRequests))
        for count in (sorted(dateDict.items(), reverse=False, key=lambda item: item[1])):
            print('{:<20s}{:>6s}'.format(count[0], str(count[1])))

    print('\nTop Clients:\n')
    print('{:<20s}{:>6s}'.format('Client IP','Requests'))
    print('{:<20s}{:>6s}'.format('---------','--------'))
    clientDict = dict(Counter(allIPs))
    increment = 0
    for count in (sorted(clientDict.items(), reverse=True, key=lambda item: item[1])):
        print('{:<20s}{:>6s}'.format(count[0], str(count[1])))
        increment += 1
        if increment >= displayTop:
            break
    

if __name__ == "__main__":
   main(sys.argv[1:])
