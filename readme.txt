=== Search Antispam ===
Contributors: danielhuesken
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CS7BVQ6TTCRYU
Tags: search, anti-spam, antispam, spam
Requires at least: 3.4.0
Tested up to: 3.5
Stable tag: 1.0

Antispam for the WordPress frontend search

== Description ==

Antispam for WordPress frontend search

Spam detection features
* A CSS hack is made
* Adds a nonce to search
* DNSBL Servers will checked for known spammers
* Referrer will checked

== Installation ==

1. Download Plugin.
2. Decompress and upload the contents of the archive into /wp-content/plugins/.
3. Activate the Plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==
= Where are the settings =
under: Settings > Search Antispam

= CSS Hack =
This option filters the most spam.
Renames the name of the input field for search and makes an extra hidden with the old name.
Checks than in with is text filled in.

= Nonce Check =
The Nonce check adds a nonce to the search field and check it.

= DNSBL Check =
The check uses a DNS lookup to opm.tornevall.org, [ix.dnsbl.manitu.net](http://www.dnsbl.manitu.net/) and [sbl/xbl.spamhaus.org](http://www.spamhaus.org/) Blacklists to check for known spammers IP's.

= Referrer Check =
Checks that the person comes form your blog.



== Screenshots ==
1. Dashboard
2. Options

== Changelog ==

= 1.0 =
* Initial release
