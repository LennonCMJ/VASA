#!/usr/bin/env python

import os
import re
import glob
from collections import defaultdict

finaldata = defaultdict(list)
ciphersuiteList = []

def get_all_ip(directory):
	# for dirname, dirnames, filenames in os.walk(directory):
	# 	print dirname

	iplist = os.listdir(directory)
	iplist.remove('targets.txt')
	return iplist

	# return list


def process_ssl_report(iplist, directory):
	
	global finaldata
	global ciphersuiteList

	cipherList = ['SSLV2','SSLV3','TLSV1_0','TLSV1_1','TLSV1_2']



	#traverse to ip folders and get sslyze and sslscan result
	for ip in iplist:
		
		ssl_dir = directory + '/' + ip + '/SSL'
		if os.path.isdir(ssl_dir):

			finaldata['cipher_header'].append('[+] Cipher\n\n')
			finaldata['cert_header_content'].append('\n[+] Certificate - Content\n\n')
			finaldata['cert_header_trust'].append('\n[+] Certificate - Trust\n\n')
			finaldata['session_header_renego'].append('\n[+] Session Renegotiations\n\n')
			finaldata['cipher_header_suites'].append('\n[+] Cipher Suites\n')

			finaldata['header'].append('\n\n\n###################################################### '+ip+' ######################################################\n\n')

			sslyze_filename = ssl_dir + '/%s_*_sslyze.txt'%ip
			

			glob_sslyze = glob.glob(sslyze_filename)

			for sslyze in glob_sslyze:

				with open(sslyze,'r') as f:
					sslyze_data = f.readlines()

				with open(directory + '/SSL_Summary.txt', 'a') as f:
					for index,subdata in enumerate(sslyze_data):
						# # do checking of lines here 

				#### Cipher checks
						if "Not vulnerable" in subdata:
							# index = sslyze_data.index(subdata)
							data = sslyze_data[index-1]
							data = (data.replace('\n','')) + ' \t\t\t\tNot vulnerable\n'
							finaldata['cipher'].append(str(data))

						elif "Server rejected" in subdata:
							data = ((sslyze_data[index-1]).replace('\n','') + ' \t\t\t\t\t\t\tNot Supported\n').replace('Cipher Suites','')
							for cipher in cipherList:
								if cipher in data:
									cipherList.remove(cipher)

							finaldata['cipher'].append(str(data))

				#### Cert content

						elif "SHA1" in subdata:
							# cert_format(subdata,5)
							finaldata['cert_content'].append(str(subdata))

						elif "Issuer" in subdata:
							# cert_format(subdata,8)
							finaldata['cert_content'].append(str(subdata))

						elif "Serial" in subdata:
							# cert_format(subdata,6)
							finaldata['cert_content'].append(str(subdata))
							
						elif "Before" in subdata:
							finaldata['cert_content'].append(str(subdata))

						elif "After" in subdata:
							finaldata['cert_content'].append(str(subdata))

						elif "Key" in subdata:
							finaldata['cert_content'].append(str(subdata))

						elif "Exponent" in subdata:
							finaldata['cert_content'].append(str(subdata))

				#### Cert trust

						elif "Hostname Validation" in subdata:
							finaldata['cert_trust'].append(str(subdata))

						elif "CA Store" in subdata:
							finaldata['cert_trust'].append(str(subdata))

						elif "Chain" in subdata:
							finaldata['cert_trust'].append(str(subdata))


				#### Session Renegotiation

						elif "initiated Renegotiation" in subdata:
							if '*' not in subdata:
								finaldata['session_renego'].append(str(subdata))

						elif "Secure Renegotiation" in subdata:
							if '*' not in subdata:
								finaldata['session_renego'].append(str(subdata))


				#### Cipher suites
						elif "Cipher Suites" in subdata:
							subdata += sslyze_data[index+1]
							cipher_re = str(re.search('\w\w\wV\d_?\d?',subdata).group(0))
							finaldata[cipher_re].append('\n'+str(subdata)+'\n')
							ciphersuiteList.append(cipher_re)

						elif "HTTP 200 OK" in subdata:
							finaldata[cipher_re].append(str(subdata))

						elif "Accepted" in subdata:
							finaldata[cipher_re].append('\n'+str(subdata)+'\n')

						elif "HTTP 200 OK" in subdata:
							finaldata[cipher_re].append(str(subdata))


					for cipher in cipherList:
						otherCiphers = '  * ' + cipher + ' : \t\t\t\t\t\t\tSupported\n'
						finaldata['cipher'].append(str(otherCiphers))


					printList = ['header','cipher_header','cipher','cert_header_content','cert_content','cert_header_trust','cert_trust','session_header_renego','session_renego','cipher_header_suites']

					for cipher in ciphersuiteList:
						printList.append(cipher)


					for i in printList:

						for data in finaldata[i]:

							insecure = 0
							cipher_re2 = ''
							weak = ['3DES','RC4']

							try:
								cipher_re2 = str(re.search('\w\w\wV\d_?\d?',i).group(0))
							except:
								pass

							if cipher_re2:

								for w in weak:
									if w in data:
										insecure = 1

								if 'TLSV1_1' == cipher_re2:
									if 'IDEA' in data:
										insecure = 1

								elif 'TLSV1' == cipher_re2:
									if 'RC2' in data:
										insecure = 1

							if insecure:
								data = data.replace("\n","") + '  *** INSECURE ***'
								f.write(data)
							else:
								f.write(data)

					finaldata.clear()
					del ciphersuiteList[:]


def cert_format(subdata,number):
	global finaldata
	tabs = '\t' * number
	data = subdata.replace(' ','')
	data = '  * ' + data
	splitdata = data.split(':')
	data = splitdata[0] + ':'+ tabs + splitdata[1]
	finaldata['cert'].append(str(data))


def gen_ssl_summary(directory):
	try:
		open(directory+'/SSL_Summary.txt','w').close()
	except:
		pass

	iplist = get_all_ip(directory)
	process_ssl_report(iplist, directory)
	print ('\n[+] SSL summary generated in %s' %directory)


def main(directory):
	gen_ssl_summary(directory)


if __name__ == '__main__':

	# Modify function's parameter if running SSL_report_gen.py on its own
	gen_ssl_summary('/root/Desktop/NetworkScan')
