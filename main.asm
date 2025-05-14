section .text
        global _start

_start:
        mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall

        mov rax, 60
        xor rbx, rbx
        syscall
