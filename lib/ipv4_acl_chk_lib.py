#
# Copyright (c) Daisuke Nakajima. All rights reserved.
#

import csv
from ipaddress import ip_network

def open_csv(inputdata):
    csv_data = []
    with open(inputdata, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            csv_data.append(row)
    return csv_data


def check_prefix_csv(csv_data):
    ''' check IP prefix of input source and destination address, port-number'''
    line_num = 2
    for acl in csv_data:
        '''Check prefix'''
        keys = ['source-address', 'destination-address']
        for key in keys:
            ipv4_prefix = acl[key]
            if ipv4_prefix != '' and ipv4_prefix != 'any':
                try:
                    ip_network(ipv4_prefix)
                except:
                    msg = 'Line {line_num} : Invalid IPv4 prefix : {key}:{ipv4_prefix} '.format(line_num=line_num,
                                                                                                key=key,
                                                                                                ipv4_prefix=ipv4_prefix)
                    print(msg)

        line_num = line_num + 1


def check_port_csv(csv_data):
    line_num = 2
    for acl in csv_data:
        '''check port number'''
        keys = ['source-port', 'destination-port']
        protocol = acl['protocol']
        if protocol in ['udp', 'tcp']:
            for key in keys:
                port_num = acl[key]
                if port_num == '':
                    if key == 'source-port' and acl['source-address'] != '' or key == 'destination-port' and acl['destination-address'] != '':
                        msg = 'Line {line_num} : Port Number is Null : {key} should set be "any"'.format(line_num=line_num,
                                                                                      key=key,
                                                                                      port_num=port_num)
                        print(msg)

                elif port_num != '':
                    if '-' not in port_num:
                        port_num = int(port_num)
                        if port_num < 0 or port_num > 65535:
                            msg = 'Line {line_num} : Invalid Port Number : {key}:{port_num} '.format(line_num=line_num,
                                                                                                     key=key,
                                                                                                     port_num=port_num)
                            print(msg)

                    elif '-' in port_num:
                        port_list = port_num.split('-')
                        for num in port_list:
                            num = int(num.rstrip(' '))
                            if num < 0 or num > 65535:
                                msg = 'Line {line_num} : Invalid Port Number : {key}:{port_num} '.format(line_num=line_num,
                                                                                                         key=key,
                                                                                                         port_num=port_num)
                                print(msg)


        elif protocol in ['ip']:
            for key in keys:
                port_num = acl[key]
                if port_num != '':
                    msg = 'Line {line_num} : Invalid Port Number : {key} Number will be ignored'.format(line_num=line_num,
                                                                                                        key=key)
                    print(msg)
        line_num = line_num + 1

def sort_prefix(csv_data):
    ''' sort csv list
        short source addreess > low port number > reject
        divide csv data to whether there source/destination prefix in the date '''
    source_destcsv = []
    sourcecsv = []
    destcsv = []
    noaddrcsv = []

    for i in csv_data:
        if i['source-address'] != '' and i['destination-address'] != '':
            source_destcsv.append(i)
        elif i['source-address'] != '':
            sourcecsv.append(i)
        elif i['destination-address'] != '':
            destcsv.append(i)
        else:
            noaddrcsv.append(i)

    sorted_sourcecsv = sorted(sorted_sourcecsv,
                              key=lambda x : ip_network(x['source-address']).network_address,
                              reverse=False)
    sorted_sourcecsv = sorted(sorted_sourcecsv,
                              key=lambda x : ip_network(x['source-address']).prefixlen,
                              reverse=True)

    sorted_destcsv = sorted(sorted_destcsv,
                            key=lambda x : ip_network(x['destination-address']).network_address,
                            reverse=False)
    sorted_destcsv = sorted(sorted_destcsv,
                            key=lambda x : ip_network(x['destination-address']).prefixlen,
                            reverse=True)

    sorted_source_destcsv = sorted(sorted_source_destcsv,
                                   key=lambda x : (ip_network(x['destination-address']).network_address,
                                                   ip_network(x['source-address']).network_address),
                                   reverse=False)
    sorted_source_destcsv = sorted(sorted_source_destcsv,
                                   key=lambda x : (ip_network(x['destination-address']).prefixlen,
                                                   ip_network(x['source-address']).prefixlen),
                                   reverse=True)

    convine_csv = sorted_source_destcsv + sorted_sourcecsv + sorted_destcsv
    for i in convine_csv:
        print(i)

def sort_port(csv_data):
    ''' sort port address
        port > range > any '''
    port_any = []
    port_unit = []
    source_range = []
    dest_range = []
    src_dest_range = []
    noport = []

    for i in csv_data:
        if 'any' in i['source-port']:
            port_any.append(i)
        elif 'any' in i['destination-port']:
            port_any.append(i)
        elif i['source-port'] != '' and '-' not in i['source-port']:
            port_unit.append(i)
        elif i['source-port'] != '' and '-' in i['source-port']:
            source_range.append(i)
        elif i['destination-port'] != '' and '-' not in i['destination-port']:
            port_unit.append(i)
        elif i['destination-port'] != '' and '-' in i['destination-port']:
            dest_range.append(i)
        else:
            noport.append(i)

    sorted_port_unit = sorted(port_unit, key=lambda x : (x['source-port'], x['destination-port']))
    sorted_source_range = sorted(source_range, key=lambda x: (port_range_calc(x['soruce-port'])))
    sorted_dest_range = sorted(dest_range, key=lambda x: (port_range_calc(x['destination-port'])))
    sorted_src_dest_port_range = sorted(dest_range, key=lambda x: (port_range_calc(x['destination-port'])))
    for i in sorted_dest_range:
        print(i)


def port_range_calc(port_range):
    port_list = port_range.split('-')
    port_num = int(port_list[1].rstrip(' ')) - int(port_list[0].rstrip(' '))
    return port_num

csv_data = open_csv('/Users/DN/PycharmProjects/junos_acl_checker/sample.csv')
#check_prefix_csv(csv_data)
#check_port_csv(csv_data)
csv_data = sort_port(csv_data)
#sort_prefix(csv_data)
