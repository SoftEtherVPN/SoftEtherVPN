import argparse

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-n', '--newline', action = 'store_true', help = 'Break line after printing version')
	args = parser.parse_args()

	end = None if args.newline else ''

	version = None
	with open('CMakeLists.txt', 'r') as file:
		for line in file:
			if 'VERSION "' in line and '.${BUILD_NUMBER}"' in line:
				line = line.replace('VERSION "', '')
				line = line[0 : line.find('.${BUILD_NUMBER}"')].strip()
				version = line
				break

	if version is None:
		raise Exception('Unable to read version from CMakeLists.txt')

	if len(version) == 0 or not '.' in version:
			raise Exception('Bad version: "{0}"'.format(version))

	print(version, end = end)

if __name__ == '__main__':
	main() 
