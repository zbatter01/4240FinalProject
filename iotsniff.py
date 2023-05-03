# Zachary Batterson
# Josiah Lamont
# Konnor Mcdowell

import argparse
from scapy.all import *


class Sniffer:
	def __init__(self,args):
		self.args = args
	def __call__(self,packet):
		if self.args.verbose:
			packet.show()
		else:
			print(packet.summary())

	def run_forever(self):
		sniff(iface=self.args.interface, prn=self, store=0)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-v','--verbose',default=False, action='store_true', help='verbose output, more information')

	parser.add_argument('-i', '--interface', type=str, required=True, help='network interface name')
	args = parser.parse_args()
	sniffer = Sniffer(args)

	sniffer.run_forever()

