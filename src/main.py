import random

from pylibpcap import wpcap, rpcap


FACTS = [b'There are over 1,000 varieties of cherries.',
         b'The botanical name of the wild cherry tree is "prunus avium".',
         b'Cherries are a good source of vitamin C.',
         b'Cherries are rich in antioxidants and anti-inflammatory compounds.',
         b'Cherries contain relatively high amounts of the metals potassium, copper, and manganese.',
         b'Never eat cherry pits! They contain small amounts of amygdalin which your body converts to cyanide.']

PADDING = [b'\xa0', b'\xa1', b'\xa2', b'\xa3', b'\xa4', b'\xa5', b'\xa6', b'\xa7', b'\xa8', b'\xa9']


def read(filename, limit=16):
    """ Read the contents of a pcap file and print details to the terminal.

    Args:
         filename (str): Path to a pcap file.
         limit (int): The maximum number of packets to read from the pcap file.
    """
    i = 0
    # Iterate through each packet read from the pcap file
    for length, t, pkt in rpcap(filename):
        print('Buf length:', length, 'Time:', t, 'Buf:', pkt)

        # Break the loop if the limit of reads has been hit
        i += 1
        if i >= limit:
            break


def generate(packet_size, num_packets, num_consumers, do_read=True):
    """ Generate a pcap file.

    Args:
         packet_size (int): The packet size in bytes.
         num_packets (int): The number of packets in the stream.
         num_consumers (int): The number of consumers intended for use.
         do_read (bool): Whether to read the file after generation or not.
    """
    filename = f'../packet_streams/{packet_size:_}B__{num_packets:_}P__{num_consumers}C.pcap'

    # Create/clear the contents of the pcap file
    open(filename, 'w').close()

    buffers = random.choices(PADDING[0:num_consumers], k=num_packets)
    data = random.choices(FACTS, k=num_packets)

    packets = []
    for buf, fact in zip(buffers, data):
        packet = buf * 16 + fact
        packet += buf * (packet_size - len(packet))
        packets.append(packet)

    # Write the new contents
    wpcap(packets, filename)

    if do_read:
        read(filename)


def calculate_consumer_count(filename):
    """ Read the contents of a pcap file and print the expected consumer counts.

    Args:
        filename (str): Path to a pcap file.
    """
    counters = [0] * 10

    # Iterate through each packet in the stream
    for _length, _t, pkt in rpcap(filename):
        # Check the packet payload to determine the expected consumer
        if pkt[0] == 160:
            counters[0] += 1
        elif pkt[0] == 161:
            counters[1] += 1
        elif pkt[0] == 162:
            counters[2] += 1
        elif pkt[0] == 163:
            counters[3] += 1
        elif pkt[0] == 164:
            counters[4] += 1
        elif pkt[0] == 165:
            counters[5] += 1
        elif pkt[0] == 166:
            counters[6] += 1
        elif pkt[0] == 167:
            counters[7] += 1
        elif pkt[0] == 168:
            counters[8] += 1
        elif pkt[0] == 169:
            counters[9] += 1

    print(f'Expected consumer counters for packet stream {filename}:')
    for i, counter in enumerate(counters):
        print(f'Consumer {i + 1}: {counter}')
    print('\n')


if __name__ == '__main__':
    #
    # Generate packets
    #

    # Vary packet count
    generate(512, 20_000, 2)
    generate(512, 40_000, 2)
    generate(512, 60_000, 2)
    generate(512, 80_000, 2)
    generate(512, 100_000, 2)
    generate(512, 120_000, 2)
    generate(512, 140_000, 2)
    generate(512, 160_000, 2)
    generate(512, 180_000, 2)
    generate(512, 200_000, 2)

    # Vary packet length
    generate(512, 100_000, 2)
    generate(1_024, 100_000, 2)
    generate(2_048, 100_000, 2)
    generate(4_096, 100_000, 2)
    generate(8_192, 100_000, 2)

    # Vary consumer count
    generate(512, 100_000, 1)
    generate(512, 100_000, 2)
    generate(512, 100_000, 3)
    generate(512, 100_000, 4)
    generate(512, 100_000, 5)
    generate(512, 100_000, 6)
    generate(512, 100_000, 7)
    generate(512, 100_000, 8)
    generate(512, 100_000, 9)
    generate(512, 100_000, 10)

    #
    # Determine expected packet counters
    #

    # Varied packet counts
    calculate_consumer_count('../packet_streams/512B__20_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__40_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__60_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__80_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__120_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__140_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__160_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__180_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__200_000P__2C.pcap')

    # Varied packet sizes
    calculate_consumer_count('../packet_streams/512B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/1_024B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/2_048B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/4_096B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/8_192B__100_000P__2C.pcap')

    # Varied consumer counts
    calculate_consumer_count('../packet_streams/512B__100_000P__1C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__2C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__3C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__4C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__5C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__6C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__7C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__8C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__9C.pcap')
    calculate_consumer_count('../packet_streams/512B__100_000P__10C.pcap')
