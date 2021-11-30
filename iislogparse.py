"""A Simple log parser and summariser for IIS log files."""
import fileinput
import sys
import getopt
from collections import Counter
from socket import gethostbyaddr

def filter_logs(key, key_values, list_of_dicts):
    """Return a list from the contents of the log file."""
    return list(filter(lambda d: d[key] not in key_values, list_of_dicts))

def display_help():
    """Display Simple help text."""
    print('\nUsage:')
    print('iislogparse.py [-h] -f <iis logfile> [-s] [-c] [-t <number>]' \
          '[-x <x.x.x.x,y.y.y.y] [-b] [-d] [-r]')
    print('\nSwitches:')
    print('{:<20s}{:>6s}'.format('-h', 'Display this help message'))
    print('{:<20s}{:>6s}'.format('-f <filename>', 'Path to the IIS log file to analyse'))
    print('{:<20s}{:>6s}'.format('-s', 'Summarise only. Do not display each request'))
    print('{:<20s}{:>6s}'.format('-c', 'Display a breakdown of HTTP status codes'))
    print('{:<20s}{:>6s}'.format('-t <number>', 'Display the top <number> clients.' \
          'Defaults to 10 if omitted)'))
    print('{:<20s}{:>6s}'.format('-x <ip,ip>', 'A comma separated list of IP addresses' \
          'to exclude from the report. No spaces allowed'))
    print('{:<20s}{:>6s}'.format('-b', 'Display a breakdown of total requests per hour'))
    print('{:<20s}{:>6s}'.format('-d', 'Display a breakdown of total requests per date'))
    print('{:<20s}{:>6s}'.format('-r', 'Attempt reverse DNS lookup of client IP addresses'))

def main(argv):
    """Parse and summarise IIS log file."""
    log_line_list = [] # a list to hold a <dict> for each line in the IIS log file
    unique_ips = []
    all_ips = []
    header = []
    status_codes = []
    hourly_requests = []
    daily_requests = []
    exclude_list = []
    summarise_only = False
    summarise_http_codes = False
    summarise_by_time = False
    summarise_by_date = False
    reverse_dns_lookup = False
    display_top = 10

    try:
        opts, args = getopt.getopt(argv, "hscbdrf:t:x:")
    except getopt.GetoptError:
        display_help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            display_help()
            sys.exit()
        if opt == '-f':
            iis_log_file = arg
        if opt == '-s':
            summarise_only = True
        if opt == '-c':
            summarise_http_codes = True
        if opt == '-b':
            summarise_by_time = True
        if opt == '-d':
            summarise_by_date = True
        if opt == '-t':
            display_top = int(arg)
        if opt == '-x':
            exclude_list = arg.split(",")
        if opt == '-r':
            reverse_dns_lookup = True

    ## Read log format header format from the IIS log
    for line in fileinput.input(iis_log_file):
        if line.startswith('#Fields:'):
            header = line.split()

    ## Remove title field:
    header.pop(0)

    for line in fileinput.input(iis_log_file):
        if not line.startswith('#'):
            fields = line.split()
            raw_log_line = dict(zip(header, fields))
            log_line_list.append(raw_log_line)

    filter_key = 'c-ip'

    filtered_log_payload = filter_logs(filter_key, exclude_list, log_line_list)

    for log_entry in filtered_log_payload:
        if not summarise_only:
            # Todo: check fields exist before printing
            print (log_entry.get('date'), log_entry.get('time'), log_entry.get('s-ip'),
                   log_entry.get('s-port'), log_entry.get('c-ip'),
                   log_entry.get('cs-method'), log_entry.get('cs-uri-stem'),
                   log_entry.get('sc-substatus'))

        all_ips.append(log_entry.get('c-ip'))

        if summarise_http_codes:
            status_codes.append(log_entry.get('sc-status'))

        if summarise_by_time:
            log_entry.get('time')[:log_entry.get('time').index(":")]
            hourly_requests.append(log_entry.get('time')[:log_entry.get('time').index(":")])

        if summarise_by_date:
            daily_requests.append(log_entry.get('date'))

        if log_entry.get('c-ip') not in unique_ips:
            unique_ips.append(log_entry.get('c-ip'))

    print('-' * 40)
    print('Analysis of IIS Log file', iis_log_file)
    print('-' * 40)
    print('{:<30s}{:>6s}'.format('Total records in log file: ', str(len(filtered_log_payload))))
    print('{:<30s}{:>6s}'.format('Total Unique Client IPs:', str(len(unique_ips))))
    if not summarise_only:
        print('{:<30s}'.format('\nUnique Client IPs:'))
        print('{:<30s}'.format('------------------'))
        for ip_address in unique_ips:
            print(ip_address)

    if summarise_http_codes:
        print('\nHTTP Status Code Breakdown:\n')
        print('{:<20s}{:>6s}'.format('Status Code', 'Occurrences'))
        print('{:<20s}{:>6s}'.format('-----------', '-----------'))
        code_dict = dict(Counter(status_codes))
        for count in sorted(code_dict.items(), reverse=True, key=lambda item: item[1]):
            print('{:<20s}{:>6s}'.format(count[0], str(count[1])))

    if summarise_by_time:
        print('\nRequest Breakdown by Hour:\n')
        print('{:<15s}{:>6s}'.format('Hour', 'Requests'))
        print('{:<15s}{:>6s}'.format('----', '--------'))
        time_dict = dict(Counter(hourly_requests))
        for count in sorted(time_dict.items(), reverse=False, key=lambda item: item[0]):
            print('{:<15s}{:>6s}'.format(count[0], str(count[1])))

    if summarise_by_date:
        print('\nRequest Breakdown by Date:\n')
        print('{:<20s}{:>6s}'.format('Date', 'Requests'))
        print('{:<20s}{:>6s}'.format('----', '--------'))
        date_dict = dict(Counter(daily_requests))
        for count in sorted(date_dict.items(), reverse=False, key=lambda item: item[1]):
            print('{:<20s}{:>6s}'.format(count[0], str(count[1])))

    print('\nTop Clients:\n')
    print('{:<15s}{:<18s}{:<8s}'.format('Requests', 'Client IP', 'FQDN'))
    print('{:<15s}{:<18s}{:<8s}'.format('--------', '---------', '----'))
    client_dict = dict(Counter(all_ips))
    increment = 0
    for count in sorted(client_dict.items(), reverse=True, key=lambda item: item[1]):
        if reverse_dns_lookup:
            try:
                dns = gethostbyaddr(count[0])[0]
            except:
                dns = '<not available>'
        else:
            dns = '-'

        print('{:<15s}{:<18s}{:<8s}'.format(str(count[1]), count[0], dns))

        increment += 1
        if increment >= display_top:
            break

if __name__ == "__main__":
    main(sys.argv[1:])
