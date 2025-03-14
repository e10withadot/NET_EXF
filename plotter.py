'''
This script generates plots based on the fields in the packets.csv file, compared to the amount of packets in that field.
You can add or remove fields in the array below to be able to generate more kinds of plots.
'''
from collections import defaultdict
import csv
import matplotlib.pyplot as plot

# ADJUST FIELDS HERE
fields = [
    "Packet Size",
    "Time to Live(TTL)",
    "TCP Window",
    "TLS Version"
]
# map of fields and their amounts
field_map = defaultdict(dict[str, int])

def dict_add(field: str, map: dict) -> tuple:
    '''
    Increment field counter if exists, add field otherwise.
    '''
    if map.get(field):
        map[field]+=1
    else:
        map[field]= 1
    return map

with open('packets.csv', 'r') as packets:
    reader= csv.DictReader(packets)
    # get fields from rows
    for row in reader:
        for field in fields:
            field_map[field] = dict_add(row[field], field_map[field])
try:
    # graph display interface
    options = '\n'.join([f'\t({i}) {field}/Amount' for i, field in enumerate(fields)])
    c = int(input(f'What would you like to see? (Ctrl + C to quit)\n{options}\n'))
    # get plot values
    xlabel= fields[c]
    map = field_map[xlabel]
    # generate plot
    plot.bar(map.keys(), sorted(map.values(), reverse=True))
    plot.title(f'{xlabel} in relation to amount')
    plot.xlabel(xlabel)
    plot.ylabel('Amount')
    plot.show()
except KeyboardInterrupt:
    print('\nOperation Cancelled.')