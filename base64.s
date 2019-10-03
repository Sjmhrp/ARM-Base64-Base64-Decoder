.THUMB

	add r1, pc, #216
	add r2, pc, #168

base64_decode:
	.byte
	add r3, pc, #77
	blx r3
	lsl r4, r0, #2
	addw r3, pc, #69
	blx r3
	lsr r6, r0, #4
	orr r4, r4, r6
	add r3, pc, #133
	blx r3
	lsl r4, r0, #4
	add r3, pc, #45
	blx r3
	lsr r6, r0, #2
	orr r4, r4, r6
	add r3, pc, #109
	blx r3
	lsl r4, r0, #6
	add r3, pc, #21
	blx r3
	orr r4, r4, r0
	addw r3, pc, #89
	blx r3
	subw r3, pc, #75
	bx r3


next:
	ldrb r0, [r1]
	cmp r0, #'='
	itt eq
	#adreq r3, output
	addeq r3, pc, #80
	bxeq r3
	add r1, #1
	cmp r0, #'A'
	sub r0, r0, #'A'
	itt lt
	addwlt r3, pc, #23
	bxlt r3
	mov r6, r6
	cmp r0, #25
	itt le
	addwle r3, pc, #9
	bxle r3
	sub r0, r0, #6

cd_return:
	mov pc, lr

cd_digit:
	add r0, r0, #17
	cmp r0, #0
	itt lt
	addlt r3, pc, #11
	bxlt r3
	add r0, r0, #52
	mov pc, lr
cd_ps:
	rsb r0, r0, #0
	lsr r0, r0, #2
	rsb r0, r0, #63
	mov pc, lr

store:
	strb r4, [r2]
	add r2, #1
	mov pc, lr
