#__Chart.d__
--

Chart.d - Tiny host(A) record DNS server designed for 802.11 phishing campaigns and acting as a malicious DNS server.

###__Description:__

Stuff and things and junk you know. Btw python probably wasnt the best choice for this project but YOLO. I personally blame the GIL but real men use stackless python anyways <3


#__Usage__
---

Chart.d is designed to be run either as a 

###__Examples:__

    $ python chartd.py

OR

    >>> import chartd
    >>> named = chartd.Chartd()
    >>> named.loadConfiguration()
    >>> named.loadZoneFile()
    >>> named.mainloop()


#__Errata & Credits__
---

#[Warning, this software is currently under heavy developement and probably wont work like you'd expect (if at all).]

###__TODO List:__

* Add Doxygen or Sphinx style documentation.
* Implement a redirection functionality in order to better mimic public APs.
* Translate a DNS zone transfer in to a chart.d zonefile.
* Start experimenting and planning with more complete DNS implementation.
* Maybe IPv6 record support (AAAA).
* Consider splitting up project in to seperate files when it gets bigger

###__Credits:__

* Person1: Thanks for that thing.
* Person2: You made that thing that does some stuff so thanks for that.
* Animal1: Down with the compsci patriarcy!
