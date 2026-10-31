# The `argus` command line tool

[← Back to Argus](../README.md)

The tool is embedded at `Argus.app/Contents/Helpers/argus`. Install a link from Settings › Command Line.

```sh
argus status
argus rules add deny --process Safari --domain doubleclick.net
argus rules add allow --process /usr/bin/curl --host api.example.com --port 443 --proto tcp --for 2h
argus profiles activate Work
argus blocklists add hagezi-light          # or any URL; see `argus blocklists catalog`
argus log --follow
argus blocked                               # what was blocked recently, and why
argus allow news.google.com                 # always allow a host (add --domain or --process NAME)
argus pause 5m && argus resume              # allow everything for a while
argus learn 3d                              # quiet learning period, then review in the app
argus test news.google.com --process Safari # what would happen, and why
argus changes && argus undo                 # recent changes; undo the latest
argus report --days 7                       # blocked, most-blocked domains, new apps
sudo argus capture start --process curl --seconds 30 && argus capture save <id> out.pcap
argus backup argus.json && argus restore argus.json --merge
argus lock                                  # changes now need an administrator (or root)
```

Run `argus help` for everything. Over SSH, `sudo argus …` administers a locked Mac.
