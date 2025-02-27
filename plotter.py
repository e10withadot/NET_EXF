import csv
import matplotlib.pyplot as plot

pkt_sizes: dict[str, int] = {}
ttls: dict[str, int] = {}
win_sizes: dict[str, int] = {}
tls_vers: dict[str, int] = {}

def dict_add(field: str, map: dict) -> tuple:
    '''
    Increment field counter if exists, add field otherwise.
    '''
    if map.get(field):
        map[field]+=1
    else:
        map[field]= 1
    return map

with open('packets.csv', 'r') as packetfile:
    reader= csv.DictReader(packetfile)
    # get fields from rows
    for row in reader:
        fields = [
            (row['Packet Size'], pkt_sizes),
            (row['Time to Live(TTL)'], ttls),
            (row['TCP Window'], win_sizes),
            (row['TLS Version'], tls_vers)
        ]
        for field, map in fields:
            map = dict_add(field, map)

# graph display interface
c = int(input('''What would you like to see? (Ctrl + C to quit)
      (1) Packet Size/Amount
      (2) Time to Live/Amount
      (3) TCP Window/Amount
      (4) TLS Version/Amount\n'''))
try:
    map: dict = {}
    xlabel: str = ''
    if c == 1:
        map= pkt_sizes
        xlabel= 'Packet Size'
    elif c == 2:
        map= ttls
        xlabel= 'Time to Live'
    elif c == 3:
        map= win_sizes
        xlabel= 'Window Size'
    elif c == 4:
        map= tls_vers
        xlabel= 'TLS Version'
    else:
        raise KeyError('Invalid value. Pick a value between 1 and 4.')

    plot.bar(map.keys(), map.values())
    plot.title(f'{xlabel} in relation to amount')
    plot.xlabel(xlabel)
    plot.ylabel('Amount')
    plot.show()
except KeyboardInterrupt:
    print('Operation Cancelled.\n')