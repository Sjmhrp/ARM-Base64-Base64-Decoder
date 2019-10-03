.text
.ARM
mov r0, #1
adr r1, string
mov r2, #14
mov r7, #4
svc #0
mov r0, #0
mov r7, #1
svc #0
string: .ascii "Hello, World!\n"
