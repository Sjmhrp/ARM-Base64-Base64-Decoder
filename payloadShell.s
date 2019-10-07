.text
.ARM
adr r0, string
mov r1, #0
mov r2, #0
mov r7, #11
svc 0
string: .asciz "/bin/sh"
