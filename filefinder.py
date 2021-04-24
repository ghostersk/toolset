#!/usr/bin/python3
import os
import sys


#print ("The script has the name %s" % (sys.argv[0]))
#print(len(sys.argv[1:]), sys.argv[1:])
class FilesEnum:
	print("You can use --help or -h to get additional commands.")
	help_txt = """
	--------------------------------------------------------------------
Arguments:	
	lo:<search location>		-Define where to start looking,
			default	is current directory

	ex:<searched extension>		-Define what file extensions to look for
					default is file format TXT
		
	ol:<output file location>	-Define combine output file location
					default is current folder
	on:<output file name>		-Define output filename
					default is "combined.txt"
	--------------------------------------------------------------------
Execution:
	-s			Makes only scan for all files, returns only TXT files by
			default
	-g			Reads all found files (with defined extension) and saves
			its content in one file - default: ./combined.txt
	--clean		Removes spaces on each line (good for lists of passwords)		
	"""
	search_location = '.'
	search_extension = 'txt'
	out_location = './'
	out_file_name = 'combined.txt'
	scan = False
	gatthering = False
	clear_spaces = False
	
	for arg in sys.argv[1:]:
		if arg[:3].upper() == 'LO:':
			search_location = arg[3:]
		elif arg[:3].upper() == 'EX:':
			search_extension = arg[3:]
		elif arg[:3].upper() == 'OL:':
			out_location = arg[3:]
		elif arg[:3].upper() == 'ON:':
			out_file_name = arg[3:]
		elif arg[:6].upper() == '--HELP' or arg[:2].upper() == '-H':
			print(help_txt)
		elif arg[:2].upper() == '-S':
			scan = True
		elif arg[:2].upper() == '-G':
			gatthering = True
		elif arg[:7].upper() == '--CLEAN':
			clear_spaces = True



	def get_allfiles(location=search_location, extension=search_extension):
		extensions = extension.split(',')
		hits = 0
		findings = []
		
		for path, subdirs, files in os.walk(location):
			for name in files:
				file_path = os.path.join(path, name)
				for extension in extensions:					
					extension = '.' + extension						
					if name.upper().endswith(extension.upper()):					
						hits += 1
						findings.append(file_path)
						print(file_path)
													
						
					
		if hits == 0:
			print(f"*** No file with {', '.join(extensions)} found.")
		else:
			print(f"*** There were {hits} files found with {', '.join(extensions)}.")
		return findings
		
	def read_file(found_file):
		with open(found_file, 'r') as notes:
			notes = notes.read()
			notes = notes.strip()
		return notes
		
	def remove_duplicates(location=out_location, name=out_file_name):
		file_name = str(location) + str(name)
		with open(file_name, 'r') as result:
			if FilesEnum.clear_spaces == False:				
				uniqlines = set(result.readlines())
			else:
				lines = result.readlines()
				lines = [line.replace(' ', '') for line in lines]
				uniqlines = set(lines)
					
			with open(file_name, 'w') as rmdup:
				rmdup.writelines(set(uniqlines))	

	def combine_txt_files(content=None, location=out_location, name=out_file_name):
		if content == None:
			content = FilesEnum.get_allfiles()
						
		for loca in content:						
			f = str(location) + str(name)
			try:
				with open(f, 'ab') as new_file:
					new_file.write(FilesEnum.read_file(loca).encode('ascii', 'ignore'))
			except Exception as err:
				print(f"\nERROR: {loca}\n{err}")
				
		FilesEnum.remove_duplicates()				
		print(f"\nSearch done, Combined file is: \n{f}")
		
	
if	FilesEnum.scan:
	FilesEnum.get_allfiles()
if 	FilesEnum.gatthering:
	FilesEnum.combine_txt_files()
			

