# Whois Crawler
The WhoisCrawler is an open-source project, dedicated in building a unix application that will be able to harvest data from whois servers and output a database, in a form able to be queried a lot faster than the server itself. The python scripts output a [Radix](https://code.google.com/p/py-radix/) type pickle, that can then be loaded by our other open-source project [CIDR-db Search](https://github.com/panagiotious/CIDR-db-Search). The user needs to obtain a pickle file of the supported format and then import the search module in order to query the database by IP.

For more information please visit the [WhoisCrawler project homepage](http://panagiotious.github.io/WhoisCrawler) on GitHub.

***
This project is built and maintained by George Louloudakis (georgelouloudakis@gmail.com) and Panagiotis Kintis (panagiotious@gmail.com). Feel free to contact us for any suggestions, bugs or ideas!
http://panagiotious.github.io/WhoisCrawler
