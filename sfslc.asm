%include '../../include/syscalls64.inc'
%include '../../include/socket.inc'
%include 'externs.inc'
%include 'equates.inc'
%include 'rodata.inc'
%include 'bss.inc'


global main

section .text
main:
    sub     rsp, 8 * 3
    
    mov     [rsp], rdi                      ; save argc
    mov     [rsp + 8], rsi                  ; save argv
    
    cmp     rdi, 1                          ; any args entered?
    je      .help                           ; no, display help msg
                                            
.Args:       
    mov     r8, NULL
    mov     rcx, long_options 
    mov     rdx, szArgs   
    mov     rsi, [rsp + 8]
    mov     rdi, [rsp]
    call    getopt_long_only 
    test    eax, eax
    js      Continue    
    
    cmp     eax, "?"                        
    je      Done    
    
    jmp     [JumpTable + 8 * rax]
    
;*******************************************
.help:
    mov     rsi, szHelpString               ; print help string
    call    PrintString
    jmp     Done                            ; and quit program

;*******************************************    
.version:
    mov     rsi, szVersion                  ; print version string
    call    PrintString
    jmp     Done                            ; and quit program

;*******************************************
.ip:
    test    qword [QueryOptions], OPT_IP    ; already have IP arg?
    jnz     .Args                            ; yes, get next arg
        
    lea     rdx, [rsp + 16]                 ; check to see if valid IP entered   
    mov     rsi, [optarg]                   ; 
    mov     rdi, AF_INET                    ; 
    call    inet_pton                       ; 
    test    eax, eax                        ; 
    jnz     .GoodIP                         ; yes it was
    
    ; invalid IP entered
    mov     rdx, szErrInvalidIP             ; err msg
    mov     rsi, qword[optarg]              ; entered IP 
    mov     rdi, fmtstr2                    ;  
    mov     rax, 0                          ; 
    call    printf                          ; print error msg
    jmp     Done                            ; quit program
    
.GoodIP:  
    mov     rdi, 16                         ; create 16 byte buffer to hold IP
    call    malloc                          ; 
    mov     [pszSpammerInfo.IP], rax        ; save pointer to IP buffer in struct
    
    mov     rsi, [optarg]
    mov     rdi, rax
    call    szCopy                          ; copy IP to buffer
    or      qword [QueryOptions], OPT_IP    ; set IP bit flag TRUE
    jmp     .Args                           ; get next arg
    
;*******************************************
.email:
    test    qword [QueryOptions], OPT_EMAIL ; already have email arg?
    jnz     .Args                            ; yes, get next arg
    
    mov     rdi, [optarg]                   ; 
    call    StrLen                          ; get length of email
    cmp     rax, MAX_EMAIL_LEN              ; 
    jle     .GoodEmailLen                   ; valid length
    
    mov     rsi, szErrInvalidEmailLen       ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
    
.GoodEmailLen:
    lea     rdi, [rax * 3 + 1]              ; email len * 3 + 1 for the NULL terminator
    call    malloc                          ; create buffer to hold encoded email
    mov     [pszSpammerInfo.Email], rax     ; save pointer email buffer in struct

    mov     rsi, [optarg]                   ; email address
    mov     rdi, rax                        ; buffer to hold encoded email
    call    Encode                          ; URL encode email
    or      qword [QueryOptions], OPT_EMAIL ; set Email bit flag TRUE
    jmp     .Args

;*******************************************
.name:
    test    qword [QueryOptions], OPT_NAME  ; already have a username?
    jnz     .Args                            ; yes, get next arg
    
    mov     rdi, [optarg]                   ; 
    call    StrLen                          ; get length of username
    cmp     rax, MAX_NAME_LEN               ;
    jle     .GoodNameLen                    ; valid length

    mov     rsi, szErrInvalidNameLen        ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
    
.GoodNameLen:
    lea     rdi, [rax * 3 + 1]              ; name len * 3 + 1 for the NULL terminator
    call    malloc                          ; create buffer to hold encoded name
    mov     [pszSpammerInfo.Name], rax      ; save pointer name buffer in struct

    mov     rsi, [optarg]                   ; name 
    mov     rdi, rax                        ; buffer to hold encoded name
    call    Encode                          ; URL encode name
    or      qword [QueryOptions], OPT_NAME  ; set Name bit flag TRUE
    jmp     .Args

;*******************************************
.apikey:
    test    qword [QueryOptions], OPT_API_KEY ; already have API key?
    jnz     .Args                           ; yup, get next arg
    
    push    rax                             ; Save option.val
    
    mov     rdi, [optarg]                   ; 
    call    StrLen                          ; make sure we have a valid key length
    cmp     rax, 14                         ; only 14 chars is valid
    je    .GoodKeyLen                       ; good to go

    pop     rax                             ; balance stack, don't care about .val
    
    mov     rsi, szErrInvalidKeyLen         ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
        
.GoodKeyLen:
    mov     rdi, rax                        ; get length of api key
    pop     rax                             ; restore option.val
    or      qword [QueryOptions], OPT_API_KEY; set out bitmask
    
    add     rdi, 1
    call    malloc                          ; create buffer to hold api key
    mov     [pszSpammerInfo.APIKey], rax
    
    mov     rsi, [optarg]                   ; api key arg string
    mov     rdi, rax                        ; our buffer
    call    strcpy                          ; copy on over
    jmp     .Args

;*******************************************
.evidence:
    test    qword [QueryOptions], OPT_EVIDENCE
    jnz      .Args
         
    mov     rdi, [optarg]
    call    StrLen
    test    rax, rax
    jz     .Args
    
.HaveEvidence:    
    lea     rdi, [rax * 3 + 1]
    call    malloc
    mov     [pszSpammerInfo.Evidence], rax
    
    mov     rsi, [optarg]
    mov     rdi, rax
    call    Encode

    or      qword [QueryOptions], OPT_EVIDENCE
    jmp     .Args
    
;*******************************************
.setwildcards:
    mov     rax, [OptionsBitmasks + 8 * rax]
    or      [QueryOptions], rax
    jmp     .Args

Done:
    mov     r14, pszSpammerInfo
    lea     r15, [pszSpammerInfo.len]
.FreeSpammerInfo:
    mov     rdi, [r14 + 8 * r15]
    call    free
    sub     r15, 1
    jns     .FreeSpammerInfo
        
    add     rsp, 8 * 3
    call    exit

;###########################################    
Continue:   
    call    __errno_location
    mov     [errno], rax
              
    test    qword [QueryOptions], OPT_QUERY ; check to see if query bitmask is set
    jnz     .PreQuery                       ; if !0, then do query
    
    test    qword [QueryOptions], OPT_SUBMIT; check to see if submit bitmask is set
    jnz      .CheckForKey                   ; if 0, then no submit

    mov     rsi, szErrNoOptions
    mov     rdi, fmtstr
    mov     rax, 0
    call    printf
    jmp     Done
    
.CheckForKey:
    test    qword [QueryOptions], OPT_API_KEY; make sure we have API Key
    jnz     .PreSubmit
    
    ; no api key, display error and run far away
    mov     rsi, szErrNeedKey
    call    PrintString
    jmp     Done  

.PreSubmit:
    ; To submit, 3 items are required, IP, Username, and email
    mov     rax, [QueryOptions]
    and     rax, 0111b
    cmp     rax, 0111b                      ; make sure we have all 3 bitmasks set
    je      .DoSubmit                       ; Phew, we got em!
    
    mov     rsi, szErrNeed3
    call    PrintString
    jmp     Done
    
.DoSubmit:
    call    SubmitStopFourmSpam
    jmp     Done
    
.PreQuery:
    mov     rax, [QueryOptions]             ; get our options
    and     rax, 0111b                      ; clear out all but lower 3 bits
    jnz     .DoQuery                        ; if !0 then we have something to search for

    mov     rsi, szErrNoSearchInfo          ; 
    call    PrintString
    jmp     Done                           ;  

.DoQuery:    
    call    QueryStopFourmSpam    

    test    qword [QueryOptions], OPT_SUBMIT
    jz      Done
    
    mov     rsi, szSubmitInfo
    call    PrintString
    jmp     .CheckForKey                           



;~ #########################################
;~ StrLen = find length of NUL terminated string
;~ in      rdi = address of string
;~ out     rax = length of string not including NUL
;~ #########################################
StrLen:
    mov     rax, 0

.Next:
    cmp     byte [rdi + rax], 0
    je      .Done
    add     rax, 1
    jmp     .Next

.Done:
    ret
    
;
;  #########################################
;  Name       : szCopy
;  Arguments  : rsi = pointer to string to copy
;               rdi = pointer to buffer to recieve string
;  Description: Copies NULL terminated string to buffer
;  Returns    : length of string minus NULL
;
szCopy:
    mov     rax, -1

.next:
    add     rax, 1
    mov     cl, BYTE [rsi + rax]  
    mov     [rdi + rax], cl
    test    cl, cl
    jnz     .next

    ret

;  #####################################################################
;  Name       : Encode
;  Arguments  : rsi = pointer to string to encode
;               rdi = pointer to buffer to hold encoded string
;  Description: Encodes unsafe characters
;  Returns    : Nothing
;
Encode:     
	dec     rdi
.nc:
    movzx   eax, byte  [rsi]
    
    test    al, al  ; al==0
    jz      .done
    
    inc     rdi
    inc     rsi
    
    cmp     al, 41h ; al=='A'
    mov     cl, al
    jb      .lA
    
    cmp     al, 5Bh ; al=='Z'
    jbe     .cpy
        
    ;al >= A
    cmp     al, 5Fh ; al=='_'
    je      .cpy
    
    ;al > _
    cmp     al, 61h ; al=='a'
    jb      .hex
    
    ; al >= a
    cmp     al, 7Ah ; al=='z'
    jbe     .cpy

.hex:
    ror     ax, 4
    mov     byte  [rdi], '%'
    shr     ah, 4
    add     rdi, 2
    add     al, 30h
    cmp     al, 3Ah
    jb      .F1
    add     al, 41h-3Ah
.F1:
    add     ah, 30h
    cmp     ah, 3Ah
    jb      .F2
    add     ah, 41h-3Ah
.F2:
    mov     word  [rdi-1], ax
    jmp     .nc
    
.cpy:
    mov     [rdi], al
    jmp     .nc
    
.space:
    mov     byte  [rdi], '+'
    jmp     .nc
    
.lA:
    cmp     al, 20h
    je      .space
    
    sub     cl, 2Dh ; al=='-'
    jz      .cpy
    dec     cl      ; al=='.'
    jz      .cpy
    
    cmp     al, 30h ; al=='0'
    jb      .hex
    
    ;al >= '0'
    cmp     al, 39h ; al=='9'
    jbe     .cpy
    
    jmp     .hex
.done:
	add		rdi, 2
    mov     byte  [rdi],0
    ret

;~ #########################################
;~ QueryStopForumSpam 
;~ in      nothing
;~ out     nothing
;~ #########################################
QueryStopFourmSpam:   
    push    r15
    push    r14
    push    r13
    push    r12
    sub     rsp, 96 + 8                 ; struct addrinfo * 2 + 8

%define _hints [rsp]    
%define _hints.ai_family dword[rsp + 4]
%define _hints.ai_socktype dword[rsp + 8]
%define _hints.ai.protocal dword[rsp + 12]

%define _servinfo [rsp + 48]
%define _servinfo.ai_family   4
%define _servinfo.ai_socktype 8
%define _servinfo.ai_protocal 12
%define _servinfo.ai_addr 24
%define _servinfo.ai_addrlen 16
%define _sockfd [rsp + 96]
%define sizeof_addrinfo 48

    mov     rdx, sizeof_addrinfo            ; 
    mov     rsi, 0                          ; 
    lea     rdi, _hints                     ; 
    call    memset                          ; clear out _hints struct
    
    mov     _hints.ai_family, AF_INET       ; IPv4
    mov     _hints.ai_socktype, SOCK_STREAM ; TCP

    lea     rcx, _servinfo                  ; 
    lea     rdx, _hints                     ; 
    mov     rsi, port                       ; 
    mov     rdi, szSFSURL                   ; 
    call    getaddrinfo                     ; fill in servinfo struct
    test    rax, rax
    jz      .Good                           ; if rax == 0, no errors

    mov     rdi, rax                        ; 
    call    gai_strerror                    ; convert err number to string
        
    mov     rsi, rax                        ; 
    mov     rdi, fmtstr                     ; 
    mov     rax, 0                          ; 
    call    printf                          ; display err message
    jmp     .ResolutionDone

.Good:                                                  
    mov     rdi, _servinfo  
    mov     edx, [rdi + _servinfo.ai_protocal]
    mov     esi, [rdi + _servinfo.ai_socktype]
    mov     edi, [rdi + _servinfo.ai_family]
    call    socket
    test    rax, rax
    jns     .DoConnect

    call    PrintError
    jmp     .SocketDone

.DoConnect:
    mov     _sockfd, rax

    mov     rdi, _servinfo
    mov     edx, [rdi + _servinfo.ai_addrlen]
    mov     rsi, [rdi + _servinfo.ai_addr]
    mov     rdi, rax
    call    connect
    test    rax, rax
    jz      .Connected
    
    call    PrintError
    jmp     .SocketDone

.Connected:
    mov     r15, GET_HEADER_LEN + SFS_QUERY_FIELDS_LEN 
.IPLen:
    mov     rdi, [pszSpammerInfo.IP]
    test    rdi, rdi
    jz      .NameLen
    call    StrLen
    add     r15, rax

.NameLen:
    mov     rdi, [pszSpammerInfo.Name]
    test    rdi, rdi
    jz      .EmailLen   
    call    StrLen
    add     r15, rax

.EmailLen:
    mov     rdi, [pszSpammerInfo.Email]
    test    rdi, rdi
    jz      .Alloc
    call    StrLen
    add     r15, rax
    
.Alloc:
    add     r15, 1
    mov     rdi, r15
    call    malloc
    mov     r14, rax

.CreateQueryHeader:
    mov     rsi, szHeadGet                  ; "GET ", 0
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szSFSQueryAPI              ; '/api?', 0
    mov     rdi, rax
    call    stpcpy

.IP_Param1:
    cmp     qword [pszSpammerInfo.IP], 0
    je      .Name_Param1

    mov     rsi, szSFSQueryIP               ; ip=
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, [pszSpammerInfo.IP]
    mov     rdi, rax
    call    stpcpy

.CheckForNameParam:
    cmp     qword [pszSpammerInfo.Name], 0
    je      .CheckForEmailParam

.NameParam:
    mov     rsi, szAmp                      ; &
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szSFSQueryName             ; name=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Name]          
    mov     rdi, rax
    call    stpcpy
            
.CheckForEmailParam:
    cmp     qword [pszSpammerInfo.Email], 0
    je     .LastParam

.EmailParam:
    mov     rsi, szAmp                      ; &
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szSFSQueryEmail            ; email=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Email]          
    mov     rdi, rax
    call    stpcpy
    jmp     .LastParam

.Name_Param1:
    cmp     qword [pszSpammerInfo.Name], 0
    je      .Email_Param1

    mov     rsi, szSFSQueryName        
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, [pszSpammerInfo.Name]
    mov     rdi, rax
    call    stpcpy
    jmp     .CheckForEmailParam

.Email_Param1:
    mov     rsi, szSFSQueryEmail            ; email=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Email]          
    mov     rdi, rax
    call    stpcpy
  
.LastParam:
    mov     rsi, szSFSQueryFmt              ; &f=json
    mov     rdi, rax
    call    stpcpy

    ;~ ; add on any options
    cmp     qword [pszSpammerInfo.Email], 0
    je     .CheckName

    mov     rcx, qword [QueryOptions]
    and     rcx, OPT_NO_EMAIL
    jz      .CheckName

    mov     rsi, szSFSNoEmail              
    mov     rdi, rax
    call    stpcpy
    
.CheckName:   
    cmp     qword [pszSpammerInfo.Name], 0
    je      .CheckIp

    mov     rcx, qword [QueryOptions]
    and     rcx, OPT_NO_NAME
    jz      .CheckIp

    mov     rsi, szSFSNoName               
    mov     rdi, rax
    call    stpcpy    

.CheckIp:
    cmp     qword [pszSpammerInfo.IP], 0
    je      .CheckAll

    mov     rcx, qword [QueryOptions]
    and     rcx, OPT_NO_IP
    jz      .CheckAll

    mov     rsi, szSFSNoIP              
    mov     rdi, rax
    call    stpcpy

.CheckAll:
    mov     rcx, qword [QueryOptions]
    and     rcx, OPT_NO_ALL
    jz      .CheckTor

    mov     rsi, szSFSNoAll             
    mov     rdi, rax
    call    stpcpy

.CheckTor:
    mov     rcx, qword [QueryOptions]
    and     rcx, OPT_NO_TOR
    jz      .Over

    mov     rsi, szSFSNoTor            
    mov     rdi, rax
    call    stpcpy  
    
.Over:  
    mov     rsi, szHeadVersion0
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szHeadHost
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szSFSURL
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szHeadAgent
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szVersion
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szHeadClose
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy
                
    mov     rdi, r14
    call    StrLen
    
    mov     rcx, 0
    mov     rdx, rax
    mov     rsi, r14
    mov     rdi, _sockfd
    call    send

    mov     rdi, r14
    call    free 

    mov     rdi, MAX_RECV_BUFFER_SIZE
    call    malloc
    mov     r15, rax

%define RecvBufOffset       r14
%define RecvBufSpaceLeft    r13

    mov     RecvBufSpaceLeft, MAX_RECV_BUFFER_SIZE - 1
    mov     RecvBufOffset, 0
.Recv:        
    mov     r11, r15
    add     r11, RecvBufOffset
    
    mov     rcx, 0
    mov     rdx, RecvBufSpaceLeft
    mov     rsi, r11
    mov     rdi, _sockfd
    call    recv
    add     RecvBufOffset, rax
    sub     RecvBufSpaceLeft, rax
    test    rax, rax
    jnz     .Recv    

    mov     byte [r15 + RecvBufOffset], 0   ; NULL terminate incomming data
    
    mov     rdi, r15
    call    GetHTTPResponseCode
    cmp     eax, "200 "
    jne     .RecvDone

.GoodResponse:
    mov     rdi, r15
    call    GetQueryReply    
    mov     r14, rax
    
.GetRetVal:
    mov     rsi, 0
    mov     sil, byte [r14]
    cmp     sil, ":"
    je      .CheckRetVal
    add     r14, 1
    jmp     .GetRetVal
    
.CheckRetVal:
    mov     rsi, 0
    mov     sil, byte [r14 + 1]
    cmp     sil, "1"
    jne      .QueryError

    ;~ mov     rsi, r14
    ;~ mov     rdi, fmtstr
    ;~ mov     rax, 0
    ;~ call    printf
    
    mov     r8, szHeadSeen
    mov     rcx, szHeadConf
    mov     rdx, szHeadFreq
    mov     rsi, szArgs
    mov     rdi, fmtrow
    mov     rax, 0
    call    printf

.GetIPInfo:    
    cmp     qword [pszSpammerInfo.IP], 0
    je      .GetNameInfo

.ParseIP:       
    mov     rsi, szIP
    mov     rdi, r14
    call    ParseSFSQuery

    mov     r13, pSFS_Reply
.DisplayIPInfo:
    mov     rsi, szRowIP
    call    PrintRow
 
.GetNameInfo:   
    cmp     qword [pszSpammerInfo.Name], 0
    je      .GetEmailInfo
    
.ParseName: 
    mov     rsi, szUserName
    mov     rdi, r14
    call    ParseSFSQuery

.DisplayNameInfo:
    mov     rsi, szRowName
    call    PrintRow
    
.GetEmailInfo:
    cmp     qword [pszSpammerInfo.Email], 0
    je      .RecvDone

.ParseEmail:    
    mov     rsi, szEmail
    mov     rdi, r14
    call    ParseSFSQuery

.DisplayEmailInfo:
    mov     rsi, szRowEmail
    call    PrintRow
    
.QueryError:
.RecvDone:    
    mov     rdi, r15
    call    free

.SocketDone:
    mov     rdi, _sockfd
    call    close
    
    mov     rdi, _servinfo
    call    freeaddrinfo

.ResolutionDone:
    add     rsp, 96 + 8
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret

;~ #########################################
;~ GetHTTPResponseCode = find HTTP Response code
;~ in      rdi = address of string to search
;~ out     rax = pointer to first char of response code
;~ #########################################
GetHTTPResponseCode:
    sub     rdi, 1
.SkipHTTP:
    add     rdi, 1
    mov     al, byte [rdi]
    cmp     al, " "
    jne     .SkipHTTP
    add     rdi, 1
    mov     rax, [rdi]
    ret

;~ #########################################
;~ GetSubmitReply = Parse HTTP reply for payload
;~ in      rdi = address of reply
;~ out     rax = pointer to null terminated payload
;~ #########################################
GetSubmitReply:
    sub     rdi, 1
.next:
    add     rdi, 1
    mov     al, byte [rdi]
    cmp     al, "<"
    jne     .next
    add     rdi, 3
    mov     rsi, rdi

    sub     rdi, 1
.FindClose:
    add     rdi, 1
    mov     al, byte [rdi]
    cmp     al, "<"
    jne     .FindClose
    mov     byte [rdi], 0
    
    mov     rax, rsi
    ret

;~ #########################################
;~ GetQueryReply = Parse HTTP reply for payload
;~ in      rdi = address of reply
;~ out     rax = pointer to payload
;~ #########################################
GetQueryReply:
    sub     rdi, 1
.next:     
    add     rdi, 1
    mov     al, byte [rdi]
    cmp     al, "{"
    jne     .next
    
    mov     rax, rdi
    ret
    
PrintError:
    sub     rsp, 8
    
    mov     rdi, [errno]
    mov     rdi, [rdi]
    call    strerror
    
    mov     rsi, rax
    call    PrintString
    
    add     rsp, 8
    ret

PrintRow:
    sub     rsp, 8
    
    mov     r13, pSFS_Reply
    mov     r8, [r13 + 8 * 2]
    mov     rcx, [r13 + 8 * 1]
    mov     rdx, [r13 + 8 * 0]
    mov     rdi, fmtrow
    mov     rax, 0
    call    printf
    
    add     rsp, 8
    ret

PrintString:
    sub     rsp, 8

    mov     rdi, fmtstr
    mov     rax, 0
    call    printf
        
    add     rsp, 8
    ret
    
;~ #########################################
;~ rsi = needle to search for
;~ rdi = haystack to search
ParseSFSQuery:
    push    r14
;ip":{"lastseen":"2014-11-07 03:50:52","frequency":5,"appears":1,"confidence":4.98}}

    call    strstr                          ; Find needle
    mov     r14, rax                        ; save pointer to first char

    mov     rsi, szAppears
    mov     rdi, rax
    call    strstr                          ; find `appears`

    mov     sil, byte[rax + 9]              ; skip over it
    cmp     sil, "0"                        ; If value != ASCII 0, not a spammer
    jne     .HaveSpammerInfo

.NoInfo:
    mov     rsi, "0"
    mov     rdi, SFSReplyStruc         
    mov     [rdi], rsi                      ; fill in structure with ASCII 0
    mov     [rdi + 32], rsi
    mov     [rdi + 48], rsi
    jmp     .Done                           ; and be done with this

.HaveSpammerInfo:
    mov     rsi, szLastSeen
    mov     rdi, r14
    call    strstr                          ; find `lastseen`
    add     rax, 11                         ; skip over it
    lea     rdi, [SFSReplyStruc.Seen]
    
.GetSeen:
    mov     sil, byte [rax]
    cmp     sil, '"'
    je      .SeenDone
    mov     byte [rdi], sil
    inc     rdi
    inc     rax
    jmp     .GetSeen

.SeenDone:
    mov     byte [rdi], 0
    
    mov     rsi, szFrequency
    mov     rdi, r14
    call    strstr
    add     rax, 11
    lea     rdi, [SFSReplyStruc.Freq]
    
.GetFreq:
    mov     sil, byte [rax]
    cmp     sil, ','
    je      .FreqDone
    mov     byte [rdi], sil
    inc     rdi
    inc     rax
    jmp     .GetFreq

.FreqDone:
    mov     byte [rdi], 0
    
    mov     rsi, szConf
    mov     rdi, r14
    call    strstr
    add     rax, 12
    lea     rdi, [SFSReplyStruc.Conf]
    
.GetConf:
    mov     sil, byte [rax]
    cmp     sil, '}'
    je      .ConfDone
    mov     byte [rdi], sil
    inc     rdi
    inc     rax
    jmp     .GetConf

.ConfDone:
     mov     byte [rdi], 0
    
.Done:
    pop     r14
    ret 

SubmitStopFourmSpam:
    push    r15
    push    r14
    push    r13
    push    r12
    sub     rsp, 96 + 8                 ; struct addrinfo * 2 + 8

%define _hints [rsp]    
%define _hints.ai_family dword[rsp + 4]
%define _hints.ai_socktype dword[rsp + 8]
%define _hints.ai.protocal dword[rsp + 12]

%define _servinfo [rsp + 48]
%define _servinfo.ai_family   4
%define _servinfo.ai_socktype 8
%define _servinfo.ai_protocal 12
%define _servinfo.ai_addr 24
%define _servinfo.ai_addrlen 16
%define _sockfd [rsp + 96]
%define sizeof_addrinfo 48

    mov     rdx, sizeof_addrinfo            ; 
    mov     rsi, 0                          ; 
    lea     rdi, _hints                     ; 
    call    memset                          ; clear out _hints struct
    
    mov     _hints.ai_family, AF_INET       ; IPv4
    mov     _hints.ai_socktype, SOCK_STREAM ; TCP

    lea     rcx, _servinfo                  ; 
    lea     rdx, _hints                     ; 
    mov     rsi, port                       ; 
    mov     rdi, szSFSURL                   ; 
    call    getaddrinfo                     ; fill in servinfo struct
    test    rax, rax
    jz      .Good                           ; if rax == 0, no errors

    mov     rdi, rax                        ; 
    call    gai_strerror                    ; convert err number to string
        
    mov     rsi, rax                        ; 
    mov     rdi, fmtstr                     ; 
    mov     rax, 0                          ; 
    call    printf                          ; display err message
    jmp     .ResolutionDone

.Good:                                                  
    mov     rdi, _servinfo  
    mov     edx, [rdi + _servinfo.ai_protocal]
    mov     esi, [rdi + _servinfo.ai_socktype]
    mov     edi, [rdi + _servinfo.ai_family]
    call    socket
    test    rax, rax
    jns     .DoConnect

    call    PrintError
    jmp     .SocketDone

.DoConnect:
    mov     _sockfd, rax

    mov     rdi, _servinfo
    mov     edx, [rdi + _servinfo.ai_addrlen]
    mov     rsi, [rdi + _servinfo.ai_addr]
    mov     rdi, rax
    call    connect
    test    rax, rax
    jz      .Connected
    
    call    PrintError
    jmp     .SocketDone

.Connected:
    mov     r15, GET_HEADER_LEN + SFS_SUBMIT_FIELDS_LEN
.IPLen:
    mov     rdi, [pszSpammerInfo.IP]
    call    StrLen
    add     r15, rax

.NameLen:
    mov     rdi, [pszSpammerInfo.Name]
    call    StrLen
    add     r15, rax

.EmailLen:
    mov     rdi, [pszSpammerInfo.Email]
    call    StrLen
    add     r15, rax

.EvidenceLen:
    test    qword [QueryOptions], OPT_EVIDENCE
    jz      .KeyLen
    
    mov     rdi, [pszSpammerInfo.Evidence]
    call    StrLen
    add     r15, rax
    
.KeyLen:
    mov     rdi, [pszSpammerInfo.APIKey]
    call    StrLen
    add     r15, rax
    
.Alloc:
    add     r15, 1
    mov     rdi, r15
    call    malloc
    mov     r14, rax

.CreateQueryHeader:
    mov     rsi, szHeadGet                  ; "GET ", 0
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szSFSSubmitAPI              ; '/add.php', 0
    mov     rdi, rax
    call    stpcpy

.NameParam:   
    mov     rsi, szSFSSubmitName             ; name=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Name]          
    mov     rdi, rax
    call    stpcpy
    
.IP_Param:
    mov     rsi, szSFSSubmitIP               ; ip=
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, [pszSpammerInfo.IP]
    mov     rdi, rax
    call    stpcpy

.EmailParam:   
    mov     rsi, szSFSSubmitEmail            ; email=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Email]          
    mov     rdi, rax
    call    stpcpy

.EvidenceParam:
    test    qword [QueryOptions], OPT_EVIDENCE
    jz      .APIKeyParam

    mov     rsi, szSFSSubmitEvidence            ; email=
    mov     rdi, rax
    call    stpcpy

    mov     rsi, [pszSpammerInfo.Evidence]          
    mov     rdi, rax
    call    stpcpy
    
.APIKeyParam:
    mov     rsi, szSFSSubmitKey
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, [pszSpammerInfo.APIKey]
    mov     rdi, rax
    call    stpcpy
    
.Over:  
    mov     rsi, szHeadVersion0
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szHeadHost
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szSFSURL
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szHeadAgent
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szVersion
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy
    
    mov     rsi, szHeadClose
    mov     rdi, rax
    call    stpcpy

    mov     rsi, szNewLine
    mov     rdi, rax
    call    stpcpy
    
    mov     rdi, r14
    call    StrLen
    
    mov     rcx, 0
    mov     rdx, rax
    mov     rsi, r14
    mov     rdi, _sockfd
    call    send

    mov     rdi, r14
    call    free 

    mov     rdi, MAX_RECV_BUFFER_SIZE
    call    malloc
    mov     r15, rax

%define RecvBufOffset       r14
%define RecvBufSpaceLeft    r13

    mov     RecvBufSpaceLeft, MAX_RECV_BUFFER_SIZE - 1
    mov     RecvBufOffset, 0
.Recv:        
    mov     r11, r15
    add     r11, RecvBufOffset
    
    mov     rcx, 0
    mov     rdx, RecvBufSpaceLeft
    mov     rsi, r11
    mov     rdi, _sockfd
    call    recv
    add     RecvBufOffset, rax
    sub     RecvBufSpaceLeft, rax
    test    rax, rax
    jnz     .Recv    

    mov     byte [r15 + RecvBufOffset], 0   ; NULL terminate incomming data
           
    mov     rdi, r15
    call    GetHTTPResponseCode
    cmp     eax, "200 "
    jne     .BadResponse
    
    mov     rsi, szAnotherNail
    call    PrintString
    jmp     .RecvDone

.BadResponse:
    mov     rdi, r15
    call    GetSubmitReply    
    
    mov     rsi, rax
    call    PrintString
    
.RecvDone:    
    mov     rdi, r15
    call    free

.SocketDone:
    mov     rdi, _sockfd
    call    close
    
    mov     rdi, _servinfo
    call    freeaddrinfo

.ResolutionDone:
    add     rsp, 96 + 8
    pop     r12
    pop     r13
    pop     r14
    pop     r15

