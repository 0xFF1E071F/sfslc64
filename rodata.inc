section .rodata
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Args
szArgs              db  "",0
szArgIP             db  "ip", 0
szArgEmail          db  "email", 0
szArgName           db  "username", 0
szArgVersion        db  "version", 0
szArgHelp           db  "help", 0
szArgHelp2          db  "?", 0
szArgNoBadEmail     db  "nobademail", 0
szArgNoBadUserName  db  "nobadusername", 0
szArgNoBadIp        db  "nobadip", 0
szArgNoBadAll       db  "nobadall", 0
szArgNoTorExit      db  "notorexit", 0
szArgAPIKey         db  "key", 0
szArgSubmit         db  "submit", 0
szArgQuery          db  "query", 0
szArgEvidence       db  "evidence", 0

;~ struct option {
    ;~ const char *name;
    ;~ int         has_arg;
    ;~ int        *flag;
    ;~ int         val;
;~ };
long_options        dq  szArgIP, required_argument, NULL, 0, \
                        szArgEmail, required_argument, NULL, 1, \
                        szArgName, required_argument, NULL, 2, \
                        szArgVersion, no_argument, NULL, 3, \
                        szArgHelp, no_argument, NULL, 4, \
                        szArgHelp2, no_argument, NULL, 5, \
                        szArgNoBadEmail, no_argument, NULL, 6, \
                        szArgNoBadUserName, no_argument, NULL, 7, \
                        szArgNoBadIp, no_argument, NULL, 8, \
                        szArgNoBadAll, no_argument, NULL, 9, \
                        szArgNoTorExit, no_argument, NULL, 10, \
                        szArgAPIKey, required_argument, NULL, 11, \
                        szArgSubmit, no_argument, NULL, 12, \
                        szArgQuery, no_argument, NULL, 13, \
                        szArgEvidence, required_argument, NULL, 14, \
                        NULL, NULL, NULL, NULL
                        
szHelpString        db  `Usage: sfslc [OPTIONS]\n`
                    db  `    --version               display version information and exit\n` 
                    db  `    --help                  display this help and exit\n`
                    db  `    --key=APIKEY            Stop Forum Spam API Key (Required for submits)\n`
                    db  `    --query                 query SFS on entered spammer info.\n`
                    db  `    --submit                submit spammer info to Stop Forum Spam database (Can be used with --query to submit after query)\n\n`
                    db  `Data to query\\submit:\n`
                    db  `    --ip=IPADDRESS          add IPADDRESS to search\n`
                    db  `    --email='EMAILADDRESS'  add EMAILADDRESS to search *Email must be enclosed in single quotes*\n`
                    db  `    --username='USERNAME'   add USERNAME to search *User Name must be enclosed in single quotes*\n`
                    db  `    --evidence='EVIDENCE'   add EVIDENCE to search (optional) *Must be enclosed in single quotes*\n\n`
                    db  `Stop Forum Spam operates a list of email domains, usernames and IP addresses that they personally consider dangerous.\n`
                    db  `You may wish to ignore these lists, in which case you need to add one or more of the following parameters:\n`
                    db  `    --nobademail            ignore email/domain list checks\n`
                    db  `    --nobadusername         ignore the username (partial string) list checks\n`
                    db  `    --nobadip               ignore the IP lists (which includes some of the Internets most hostile spam friendly networks)\n`
                    db  `    --nobadall              ignore all wildcard checks (same as above 3)\n`
                    db  `    --notorexit             ignore valid (good) Tor exit node IPs\n`, 0


JumpTable           dq  main.ip, main.email, main.name, main.version, main.help, main.help, \
                        main.setwildcards, main.setwildcards, main.setwildcards, main.setwildcards, \
                        main.setwildcards, main.apikey, main.setwildcards, main.setwildcards, main.evidence

OptionsBitmasks     dq  OPT_IP, OPT_NAME, OPT_EMAIL, 0, 0, 0, OPT_NO_EMAIL, OPT_NO_NAME, \
                        OPT_NO_IP, OPT_NO_ALL, OPT_NO_TOR, OPT_API_KEY, OPT_SUBMIT, OPT_QUERY, OPT_EVIDENCE

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Error strings
szErrInvalidIP          db  "is not a valid IP address", 0
szErrInvalidEmailLen    db  "Email entered is too long, valid is less than ", MAX_EMAIL_LEN_STR, " characters", 0
szErrInvalidNameLen     db  "Name entered is too long, valid is less than ", MAX_NAME_LEN_STR, " characters", 0   
szErrNoSearchInfo       db  "Nothing to search for!  You forgot to enter an IP, Email, or Username!",  10, "--help for usage", 0
szErrInvalidKeyLen      db  "Invalid API key length!", 0
szErrNeedKey            db  "Need API Key to submit, use --key option", 0
szErrNeed3              db 'The following fields are required to submit:', 10
                        db '    IP', 10
                        db '    UserName', 10
                        db '    Email', 10
                        db 'The evidence field is optional', 0
szErrNoOptions          db "Not sure what to do, you forgot to use: --query or --submit.  Try again, I will be waiting here.", 0

fmtstr      db `%s\n`, 0
fmtstr2     db `%s %s\n`, 0
fmtrow      db `%-8s %-16s %-8s %-16s\n`, 0

;~ ##### Stop Forum Spam
szSFSURL                db 'www.stopforumspam.com', 0
SFS_BASE_URL_LEN        equ $ - szSFSURL
szSFSQueryAPI           db '/api?', 0
szSFSQueryFmt           db '&f=json', 0
szSFSQueryEmail         db 'email=', 0
szSFSQueryIP            db 'ip=', 0
szSFSQueryName          db 'username=', 0
szSFSNoEmail            db '&nobademail', 0
szSFSNoName             db '&nobadusername', 0
szSFSNoIP               db '&nobadip', 0
szSFSNoAll              db '&nobadall', 0
szSFSNoTor              db '&notorexit', 0
szAmp                   db '&', 0
SFS_QUERY_FIELDS_LEN    equ ($ - szSFSURL) + 1

szSFSSubmitAPI          db '/add.php', 0
szSFSSubmitName         db '?username=', 0
szSFSSubmitIP           db '&ip_addr=', 0
szSFSSubmitEmail        db '&email=', 0
szSFSSubmitEvidence     db '&evidence=', 0
szSFSSubmitKey          db '&api_key=', 0
SFS_SUBMIT_FIELDS_LEN   equ ($ - szSFSSubmitAPI) + SFS_BASE_URL_LEN

port                    db '80', 0

GetHeader:
szHeadGet               db  "GET ", 0
szHeadVersion0       	db  " HTTP/1.0", 13, 10, 0
szHeadHost          	db  "Host: ", 0
szNewLine				db	13, 10, 0
szHeadAgent         	db  "User-agent: ", 0
szHeadClose         	db  "Connection: close", 13, 10, 0
szVersion               db  "Stop Forum Spam List Checker ", SFSLC_VERSION, " (Linux)", 0
GET_HEADER_LEN          equ $ - GetHeader 

szIP                    db 'ip', 0
szUserName              db 'username', 0
szAppears               db 'appears', 0
szLastSeen              db 'lastseen', 0
szFrequency             db 'frequency', 0
szConf                  db 'confidence', 0
szEmail                 db 'email', 0

szHeadFreq              db 'Frequency', 0
szHeadConf              db 'Conf.', 0
szHeadSeen              db 'Last Seen', 0

szRowIP                 db 'IP:', 0
szRowName               db 'Name:', 0
szRowEmail              db 'Email:', 0

szSubmitInfo            db "Submiting info to SFS, hold on.", 0
szAnotherNail			db "There goes another nail in the coffin!", 0

pSFS_Reply:
        dq  SFSReplyStruc.Freq, SFSReplyStruc.Conf, SFSReplyStruc.Seen
