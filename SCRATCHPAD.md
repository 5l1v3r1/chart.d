__TODO__
========

* Use new naming convention
* Refactor and restructure existing code
* Change format of configuration files to JSON
* Possibly implement a more complete DNS protocol spec


__FUTURE BUGS & THOUGHTS__
==========================

* The best way to integrate this thing in to wifiphisher would be to have it read the main configuration, fetch that section of the dictionary and write it to a tempfile and have chartd just read that. This will also allow chartd to run as a stand-alone DNS server for custom usage. (Could StringIO help us with this? Disk I/O is so slow and why do it if we can avoid it.)

* At a later point we should possibly consider adding support for implementing actual DNS zones as well as different kinds of DNS records  (A, MX, PTR, etc). This could allow us to run a zone transfer on a domain and mirror this for a more advanced spear-phishing attack. Doing this in bind would be a massive pain in the ass so this would speed things up on blackbox engagements.

* Stress test the server to see how many request/s it can handle as well as what parts could benefit from greater optimizations. 
