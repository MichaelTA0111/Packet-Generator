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
    filename = f'../output/{packet_size:_}B__{num_packets:_}P__{num_consumers}C.pcap'

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
