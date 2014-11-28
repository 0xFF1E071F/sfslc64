TRUE            equ 1
FALSE           equ 0
NULL            equ 0
;AF_INET         equ 2
MAX_RECV_BUFFER_SIZE equ	8192
%defstr HTTP_OK  200
;%define errno __errno_location

%macro equstr 1
	%00		equ	%1
	%defstr		%00_STR	%1
%endmacro

MAX_EMAIL_LEN	equstr 254
MAX_NAME_LEN    equstr 132
%defstr SFSLC_VERSION 1.0.0.2

;~ ENC_EMAIL_LEN   equ (MAX_EMAIL_LEN * 3) + 1
;~ ENC_NAME_LEN    equ (MAX_NAME_LEN * 3) + 1

;~ struct option has_arg values
no_argument         equ 0
required_argument   equ 1
optional_argument   equ 2

;~ Bitmasks for Data to query
OPT_IP          equ 1
OPT_NAME        equ 2
OPT_EMAIL       equ 4

;~ Bitmasks for SFS Options
OPT_NO_EMAIL    equ 8   ; &nobademail
OPT_NO_NAME     equ 16  ; &nobadusername
OPT_NO_IP       equ 32  ; &nobadip
OPT_NO_ALL      equ 64  ; &nobadall
OPT_NO_TOR      equ 128 ; &notorexit

OPT_API_KEY     equ 256 ; API Key
OPT_SUBMIT      equ 512 ; submit option
OPT_QUERY       equ 1024; query option
OPT_EVIDENCE    equ 2048; evidence option

             
