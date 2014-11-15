#___Chart.d___
--

Chart.d - Tiny host(A) record DNS server designed for 802.11 phishing campaigns and acting as a malicious DNS server.

###__Description:__

Stuff and things and junk you know. Btw python probably wasnt the best choice for this project but YOLO. I personally blame the GIL but real men use stackless python anyways <3


#__Usage__
---

As a stand-alone service :
* `python chartd.py`

As python library:
* `>>> import chartd`
* `>>> named = chartd.Chartd()`
* `>>> named.loadConfiguration()`
* `>>> named.loadZoneFile()`
* `>>> named.mainloop()`

###__Examples:__

* `A single well thought out, beautiful example usage.`


#__Errata & Credits__
---

#[Warning, this software is currently under heavy developement and probably wont work like you'd expect (if at all).]

###__Things To Do:__
* Actually Finish the README.
* Finishing the program might not hurt either...
* Pick up milk.
* Fire the idiot who named the logger instance packtdLogger.

* Implement a redirection functionality in order to better mimic open APs
* Translate a DNS zone transfer in to a chart.d zonefile
* Start experimenting and planning with more complete DNS implementation 

###__Credits:__
* Person1: Thanks for that thing.
* Person2: You made that thing that does some stuff so thanks for that.
* Animal1: Down with the compsci patriarcy!
