What
---

This standalone script is a POP3 server that gets the data from an upstream IMAP server.

How
---

It detects the hostname of the IMAP server through the email address that is used as login. It does this by picking the
domain part of the email address and looks up the autodiscover endpoint for that domain. This works great with Amazon
WorkMail.

Example:

If your username is `fluffy@bunny.com`, the IMAP endpoint is detected by looking up `autodiscover.bunny.com`. This
should point to the existing autodiscover service, for instance `autodiscover.mail.us-west-2.awsapps.com`. Then it
replaces `autodiscover` with `imap` and we have ourselves an endpoint.

But if you don't like that you can use the `--endpoint` argument to force a static upstream IMAP server.

The program does a thread per POP3 connection but don't expect this to scale for many users. It only listens on
localhost and on the non-privileged port 1110. If you want you can run it as root and use `--port 110` to get it on the
actual POP3 service port.

Bugs
---

Yep, probably. There is bound to be some race condition with the IMAP connection caching, probably other bugs too.  Note
that this is just a proxy. If there are issues upstream in the IMAP service or in the email data served, things might
not work too well in that case. You can try the `--debug` parameter to get more information. You are on your own and I'm
not going to help you debug issues.

Also error handling isn't all that. I wouldn't be surprised if connections die now and again.

This proxy ignores the `RSET` command. If you've sent `DELE` the email will be removed from the upstream server after
the session. If for some reason the IMAP `EXPUNGE` did not happen, you will download those messages again.

Requirements
---

I tested this with python3.7, but looking at the feature set used it should work with python3.5 and later. No other
modules are needed.
