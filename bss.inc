section .bss    
QueryOptions        resq 1
errno               resq 1

pszSpammerInfo:
    .IP             resq 1
    .Name           resq 1
    .Email          resq 1
    .Evidence       resq 1
    .APIKey         resq 1
    .len            equ ($ - pszSpammerInfo) / 8 - 1

SFSReplyStruc:
    .Freq           resb 32
    .Conf           resb 16 
    .Seen           resb 32      


