dict_protocol={
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP'
}

dict_option_IP={
    '0': 'EOOL',
    '1': 'NOP',
    '7': 'RR',
    '68': 'TS',
    '131': 'LSR',
    '137': 'SSR',
}

dict_YN={
    '0': 'No',
    '1': 'Yes',
}

dict_CN={
    '0': 'Control',
    '1': 'No control'
}

dict_Opcode={
    '0': 'Standard query',
    '1': 'IQuery',
    '2': 'Status',
    '3-15': 'Reserved/Registration'
}

dict_QR={
    '0': 'query',
    '1': 'response'
}

dict_AA={
    '0': 'Server is not an authority for domain',
    '1': 'Server is an authority on the domain'
}

dict_TC={
    '0': 'Message is not truncated',
    '1': 'Message is truncated'
}

dict_RD={
    '0': 'Don t do query recursively',
    '1': 'Do query recursively'
}

dict_RA={
    '0': 'Sever can not do recursive queries',
    '1': 'Sever can do recursive queries'
}

dict_RCode={
    '0': 'No Error',
    '1': 'Format Error',
    '2': 'Server Failure',
    '3': 'Name Error',
    '4': 'Not Implemented',
    '5': 'Refused',
    '6-15': 'Reserved'
}

dict_type_queries={
    '1': 'A',
    '2': 'NS',
    '3': 'MD',
    '4': 'MF',
    '5': 'CNAME',
    '6': 'SOA',
    '7': 'MB',
    '8': 'MG',
    '9': 'MR',
    '10': 'NULL',
    '12': 'PTR',
    '13': 'HINFO',
    '14': 'MINFO',
}

dict_type_queries_name={
    'NS': 'Name Server',
    'MD': 'Mail Destination',
    'MF': 'Mail Forwarder',
    'CNAME': 'CNAME',
    'MB': "MailBox Domain",
    'MG': 'Mail Group Member',
    'MR': 'Mail Rename Domain',
    'PTR': 'Domain Name',
}

dict_type_class={
    '1': 'In',
    '2': 'Cs',
    '3': 'Ch',
    '4': 'Hs',
}
