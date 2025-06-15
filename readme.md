# dns-tunneling

a proof of concept for exfiltrating files over dns using a custom client and server. the client encodes and transmits file content via dns queries, while the server decodes and reconstructs the files.

![DNS Tunneling Explained](https://www.akamai.com/site/en/images/article/2023/what-is-dns-tunneling.png)

**Figure**: Diagram explaining [DNS Tunneling](https://www.akamai.com/glossary/what-is-dns-tunneling) – a method of bypassing network restrictions by encapsulating data within DNS queries and responses.

> **tested on linux; some features are currently linux-specific. cross-platform support and a better client build process are in progress.**

## features

* base32-encoded payloads embedded in dns queries
* chunked file transmission with ordered reconstruction
* server-side reconstruction triggered by control message (`!rebuild!`)
* supports exfiltration of multiple files per session
* works across platforms (linux, macos, windows)

## structure

```
.
├── client.py           # sends file chunks over dns
├── server.py           # receives and reconstructs files
├── dumped_data/        # output directory for reconstructed files
├── testing_data/       # example input files to test exfiltration
└── readme.md
```

## how it works

1. the client reads and base64-encodes a file.
2. the payload is chunked and formatted as:
`filename|--chunk_index|--chunk_data`
3. each chunk is base32-encoded and sent via a dns a record query.
4. the server listens on port 53, parses incoming queries, and writes chunk data.
5. once the `!rebuild!` control message is received, the server reconstructs the file.

## usage

### run server (requires root to bind port 53)

```bash
sudo python3 server.py
```

### run client

edit `client.py` to set:

* `dns_server`: ip of the server
* `search_dir`: directory to search for files
* `exts`: file extensions to include

then run:

```bash
python3 client.py
```

## dependencies

* python 3.6+
* no external libraries required

## warnings

* this tool is for educational purposes only.
* do not use in unauthorized environments.
* exfiltration is detectable by network monitoring tools.

## todo

* enhance file discovery process
* add client build process for easier distribution (pyinstaller)
* add encryption (aes-256) to payloads
* implement optional response validation from server
* support dynamic domain generation (ddg)
* add gui to client or possibility to run in background !!!!! :(
