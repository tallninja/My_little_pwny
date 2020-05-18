#!/usr/bin/python3

#Author: Ernest Wambua
#Date: Sun May 17 21:00 hrs
#Versio: 2.0


import requests
import sys
import os
import hashlib
import termcolor
from optparse import OptionParser

class Pwny():
	'''Does all the password manipulations'''
	def __init__(self, password):
		self.password = password
		self.url = "https://api.pwnedpasswords.com/range/"
		self.breached = False

	def connection(self):
		'''Will test connection to the haveibeenpwned site'''
		test_string = "AAF4C"
		test_url = self.url + test_string 
		response = requests.get(test_url)
		return_code = response.status_code

		if return_code == 200:
			return True
		else:
			return False

	def hash_password(self):
		'''Will hash the password string before processing'''
		password_hash = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
		return password_hash


	def password_trim(self):
		'''Trim the password into two parts for querying'''
		hash = self.hash_password()
		head = hash[:5]
		tail = hash[5:]
		return [head, tail]

	def query_password(self):
		query_url = self.url
		query_head = self.password_trim()[0]
		query_request = query_url + query_head
		query_response = requests.get(query_request).text.splitlines()

		return query_response



	def parse_response(self):
		'''Parse the response we get from the response split the tail from the breaches'''
		password_tail = self.password_trim()[1]
		data = self.query_password()

		for each_tail in data:
			results = each_tail.split(':')
			tail = results[0]
			breaches = results[1]

			if tail == password_tail:
				return breaches
				break

		return 0


	def check(self):
		'''Informing the user whether the password is safe or not'''
		breaches = self.parse_response()
		if breaches:
			print(f"[{termcolor.colored('!!!', 'red', attrs=['blink'])}] {self.password} >>> is NOT safe: Breaches = {termcolor.colored(breaches, 'red')}")
		else:
			print(f"[{termcolor.colored('***', 'green')}] {self.password} >>> is SAFE: Breaches = {termcolor.colored('None', 'green')}")





def main():
	'''This is the main function which will be executed when the program is run'''
	parser = OptionParser()
	parser.add_option("-f", "-F",  "--file", dest='filename', help='Input file to read the passwords preferabbly a CSV file or the path to the file')
	(options, args) = parser.parse_args()

	file = options.filename
	passwords = sys.argv[1:]

	if file:
		if os.path.isfile(file):	#checks if file exists
			with open(file, "r") as file:
				data = file.read()
				if data:	#checks whether the file is empty
					try:	#checks if file is readable
						password_list = data.split(",")
					except Exception as e:
						print("Invalid file type please use a CSV file for better results")

					for password in password_list:
						try:
							Pwny(password).connection()
							Pwny(password.strip()).check()

						except Exception as e:
							("Print connection timed out ! Check your internet connection and try again")
				else:
					print("The file is empty")

		else:
			print("file does not exist")

	elif passwords:
		password_list = [password for password in passwords]

		for password in password_list:
			try:
				Pwny(password).connection()
				Pwny(password).check()

			except Exception as e:
				print("Connection Timed out ! Check your internet connection and try again")

	else:
		print("Enter -h or --help for help options")




if __name__=='__main__':
	main()





