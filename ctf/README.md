# CTF

- `setup_flag.py` puts the flag in `server/sftp_root/projects/confidential/flag.txt` and a hint in `/public`.
  Running it again restores the flag if it was changed.
- `attack.py` logs in as a user and tries to get the flag in every way we could think of.
- `writeup/CTF_writeup.html` is the source of `CTF_writeup.pdf` (repo root). To rebuild the PDF, open it in
  a browser and print to PDF, or:
  `msedge --headless --no-pdf-header-footer --print-to-pdf=CTF_writeup.pdf ctf/writeup/CTF_writeup.html`
