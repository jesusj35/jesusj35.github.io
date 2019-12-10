from nltk.stem import PorterStemmer
from nltk.tokenize import sent_tokenize, word_tokenize
import json
import pprint
import re
from string import punctuation

# dictionary for tracking words : entries
word_entry = {}

# intersection algorithm 
def intersection(p1, p2, grid):
	queryresult = []
	p1 = p1.lower()
	p2 = p2.lower()
	p1 = ps.stem(p1)
	p2 = ps.stem(p2)
	
	# check if word1 and 2 are actually in the inverted index
	if p1 not in grid:
		return 'word1 not in cve'

	if p2 not in grid:
		return 'word2 not in cve'

	# get the list for word1
	p1list = sorted(grid[p1])
	
	# get the list for word1
	p2list = sorted(grid[p2])
	
	# printing sorted lists for debugging
	# print(p1)
	# print(p1list)
	# print(p2)
	# print(p2list)
	
	# starting counters for traversing through the lists
	x = 0
	y = 0
	yesmatch = False
	
	while x < len(p1list) and y < len(p2list):
		if p1list[x] == p2list[y]:
			queryresult.append(p1list[x])
			yesmatch = True
			x = x + 1
			y = y + 1
		elif p1list[x] < p2list[y]:
			x = x + 1
		else:
			y = y + 1
	if yesmatch is False:
		queryresult.append(-1)
	return queryresult

# function to add a word:entry mapping to our dictionary
def add_word_entry(word, entry, word_dict):
	# convert all to lower
	entry = entry.lower()
 
	# test for existence
	if word not in word_dict:
		# add new list if not there
		word_dict[word] = []
		
	# now, either way, append new entry if not already there
	if entry not in word_dict[word]:
		word_dict[word].append(entry)

# open json file and convert to dict
with open('nvd.json', 'r') as f:
	nvdinfo = json.load(f)
	
# iterate through dict that json.load returned
for cve in nvdinfo['CVE_Items']:
	ps = PorterStemmer()
	# add ID as-is
	id = cve['cve']['CVE_data_meta']['ID']
	id = id.lower()
	add_word_entry(id, id, word_entry)
	
	# parse description by spaces
	description = cve['cve']['description']['description_data'][0]['value']
	description = description.lower()
	#desc_words = re.split(r'[,-_."”“+:/!;~?%$\s\'\(\\)()(””)]+', description)
	
	# split text
	desc_words = description.split()
	
	# remove punctiation from right side of word
	for i, words in enumerate(desc_words):
		desc_words[i] = words.rstrip(punctuation)
	
	# remove punctiation from left side of word
	for i, words in enumerate(desc_words):
		desc_words[i] = words.lstrip(punctuation)
	
	# add words
	for word in desc_words:
		add_word_entry(ps.stem(word), id, word_entry)
	
	# make sure this entry has a 'basemetricV3' in the impact object
	impact = cve['impact']
	if 'basemetricV3' in impact:
		# add base score as string as a word
		baseScore = str(impact['basemetricV3']['cvssV3']['baseScore'])
		add_word_entry(baseScore, id, word_entry)
	
	# add published date    
	date = cve['publishedDate']
	add_word_entry(date, id, word_entry)
	
# sort list of dict keys
sorted_words = sorted(list(word_entry.keys()))

#query to check
word1 = 'overflow'
word2 = 'android'

#calling intersection
print("Result")
print(intersection(word1, word2, word_entry))

#create file to write inverted index to
out_file = open('invertedindex.txt', 'w')

#print inverted index
for word in sorted_words:
	# print key first
	print("{:<60} ".format(word), end='', file = out_file)
	
	# then the entries comma separated
	print(', '.join(sorted(word_entry[word])), file = out_file)
	
#close file
out_file.close()

