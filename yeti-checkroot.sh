#! /bin/sh

# Using Stephane Bortzmeyer's TLS-secured open resolver for lookups.
# 
# http://lists.yeti-dns.org/pipermail/discuss/2016-December/000750.html
#
exec python3 soaping.py --resolver 2001:4b98:dc2:43:216:3eff:fea9:41a --tls .
