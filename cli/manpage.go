package cli

// manPageContent is the troff source for the man page.
// Pipe through "man -l -" to render it, or use "rofk man | man -l -".
const manPageContent = `.TH ROFK 1 "2026" "Route Fork" "User Commands"
.SH NAME
rofk \- SOCKS proxy\-aware port scanner with nmap integration
.SH SYNOPSIS
.B rofk
\fB\-proxlist\fR \fIfile\fR
\fB\-ip\fR \fItarget\fR
[\fIoptions\fR]
[\fInmap\-flags\fR...]
.PP
.B rofk
\fBvalidate\fR [\fIflags\fR]
.PP
.B rofk
\fBscan\fR [\fIflags\fR]
.PP
.B rofk
[\fBman\fR|\fBhelp\fR]
.SH DESCRIPTION
.B rofk
routes port scans through SOCKS4/SOCKS5 proxy pools.
It starts a local SOCKS4 relay so that
.BR nmap (1)
can be used without proxychains or any other wrapper \(em just pass
.B \-proxlist
and
.B \-ip
and every other flag goes straight to nmap unchanged.
.PP
Running without arguments opens the graphical user interface.
.SH OPTIONS
.SS "Proxy-manager flags"
.TP
\fB\-proxlist\fR \fIfile\fR
Proxy list file.  One entry per line.  Accepted formats:
.nf
  host:port
  socks4://host:port
  socks5://host:port
  socks5://user:pass@host:port
.fi
.TP
\fB\-ip\fR \fItarget\fR
Target host, IP, or CIDR (e.g. 192.168.1.0/24).
Also accepted as a positional argument.
.TP
\fB\-p\fR \fIports\fR
Port spec: 80,443 or 1\-1024.  Forwarded to nmap as well.
.TP
\fB\-out\fR \fIfile\fR
Write results to this file (format controlled by \fB\-type\fR).
.TP
\fB\-type\fR \fIfmt\fR
Output format: txt (default), json, xml, csv.
.TP
\fB\-tool\fR \fIname\fR
nmap (default) or builtin (pure-Go TCP connect).
.TP
\fB\-conc\fR \fIN\fR
Concurrency for built-in scanner (default: 200).
.TP
\fB\-timeout\fR \fIsec\fR
Connect timeout seconds (default: 5).
.TP
\fB\-rotate\fR / \fB\-no\-rotate\fR
Rotate proxy between targets (default: on).
.TP
\fB\-wrap\fR / \fB\-no\-wrap\fR
Wrap pool when exhausted (default: on).
.TP
\fB\-nmap\-path\fR \fIpath\fR
Path to nmap binary; saved to ~/.config/rofk/config.
.SS "nmap pass-through"
Every unrecognised flag is forwarded to nmap unchanged.
.SH EXAMPLES
.nf
  rofk \-proxlist ~/proxies.txt \-ip 192.168.1.2 \-p 80,443 \-sV
  rofk \-proxlist ~/proxies.txt \-ip 10.0.0.0/24 \-T4 \-A \-type json \-out r.json
  rofk validate \-f raw.txt \-o live.txt \-t 200
.fi
.SH FILES
.TP
.I ~/.config/rofk/config
Stores nmap_path and other persistent settings.
.SH SEE ALSO
.BR nmap (1)
`
