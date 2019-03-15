# __Chart.d__

__Warning, this software is currently under heavy developement and probably wont work like you'd expect (if at all).__

Chart.d - Tiny host(A) record DNS server designed for 802.11 phishing campaigns and acting as a malicious DNS server. Python was probably not the best choice for this project but YOLO. I personally blame the GIL but real men use stackless python anyways <3

## __Examples:__

    $ python chartd.py

OR

    >>> import chartd
    >>> named = chartd.Chartd()
    >>> named.loadConfiguration()
    >>> named.loadZoneFile()
    >>> named.mainloop()
