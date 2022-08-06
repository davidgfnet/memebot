
Telegram Meme Maker Bot
=======================

You may find this bot at https://t.me/mememakebot

How to run your own
-------------------

Build the bot running `make`. You will need to run it as a fastcgi service:

```
spawn-fcgi -u unixuser -s /path/to/socket -n /path/to/bot /path/to/service.conf
```

The only argument is the config file, which should look like:

```
nthreads = 10;
tg-apikey = "your-telegram-api-key-from-botfather";
base_url = "https://yourserver.com/somepath";
logs = "/var/log/somelog";
imgflip_username = "imgflip-user";
imgflip_password = "imgflip-pass";
```

Your server should be forwarding all the requests via FastCGI to the right socket.
You also need to provide the bot with the external URL (ideally https) so that
images can be fetcher by the Telegram servers.

Memes are generated via api.imgflip.com, where templates are fetched too. Make sure
your account works and you can log in.

You can tweak stuff like log directory (will generate daily logs but won't garbage
collect anything, you'll need to use an external tool) or the number of threads.

