import random

from pylibpcap import wpcap, rpcap


PACKETS = [(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
            b'There are over 1,000 varieties of cherries.'
            b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'),

           (b'\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb'
            b'The botanical name of the wild cherry tree is "prunus avium".'
            b'\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb'),

           (b'\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc'
            b'Cherries are a good source of vitamin C.'
            b'\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc'),

           (b'\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd'
            b'Cherries are rich in antioxidants and anti-inflammatory compounds.'
            b'\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd'),

           (b'\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee'
            b'Cherries contain relatively high amounts of the metals potassium, copper, and manganese.'
            b'\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee'),

           (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
            b'Never eat cherry pits! They contain small amounts of amygdalin which your body converts to cyanide.'
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')]


def read(file, limit=16):
    """ Read the contents of a pcap file and print details to the terminal.

    Args:
         file (str): Path to a pcap file.
         limit (int): The maximum number of packets to read from the pcap file.
    """
    i = 0
    # Iterate through each packet read from the pcap file
    for length, t, pkt in rpcap(file):
        print('Buf length:', length, 'Time:', t, 'Buf:', pkt)

        # Break the loop if the limit of reads has been hit
        i += 1
        if i >= limit:
            break


def generate(file, contents, do_read=True):
    """ Generate a pcap file.

    Args:
         file (str): Name of the pcap file to be created.
         contents (list(str)): The packet contents to be written to the pcap file.
         do_read (bool): Whether to read the file after generation or not.
    """
    # Create/clear the contents of the pcap file
    open(file, 'w').close()

    # Write the new contents
    wpcap(contents, file)

    if do_read:
        read(file)


if __name__ == '__main__':
    # Create a simple pcap file with 6 distinct packets
    generate('./output/cherry_facts.pcap', PACKETS)

    # Create 10,000 unequally sized packets
    generate('./output/random_cherries.pcap', random.choices(PACKETS, k=10_000))

    # Create 20,000 equally sized packets
    generate('./output/constant_cherries.pcap', PACKETS[0:1] * 20_000)
