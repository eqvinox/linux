.. SPDX-License-Identifier: GPL-2.0

====================================
IPv6 source address selection trivia
====================================


RFC6724 rule 5.5 support
------------------------

RFC6724 rule 5.5 is a very short paragraph in a complex RFC that has turned
out quite tricky, but also immensely useful in multihoming scenarios.  For
reference, it says:

::

   Rule 5.5: Prefer addresses in a prefix advertised by the next-hop.
   If SA or SA's prefix is assigned by the selected next-hop that will
   be used to send to D and SB or SB's prefix is assigned by a different
   next-hop, then prefer SA.  Similarly, if SB or SB's prefix is
   assigned by the next-hop that will be used to send to D and SA or
   SA's prefix is assigned by a different next-hop, then prefer SB.

The way this works on Linux is as follows:

- prior to any source address selection happening, when receiving a RA, more
  than the installation of a default route (or ::/128 route) needs to happen:
  for each PIO, a source-specific (subtree) route is *additionally* installed.
  The effect of this is that *after* a source address has been selected, one
  of the routers that advertised it will remain in use (this is *not* RFC 6724
  related, but rather RFC 8028.)  At the same time, these extra routes serve
  to remember which router advertised what.

- per usual, a route lookup for the IPv6 destination address in consideration
  is done first.  This is passed around in kernel as a dst_entry.

- the source address selection code iterates through the various rules in
  RFC 6724.

- if/when rule 5.5 is reached, first of all, there is a check if *any* source
  specific routes exist in the routing table.  If there are none, the entire
  code for 5.5 is skipped because it cannot have any effect, but is not free
  to execute (can involve multiple routing lookups.)  **In applications that
  use a lot of unbound (e.g. UDP) sockets, installing subtree routes should
  therefore be avoided to not incur this cost on each source address selection
  pass.**  Alternatively, applications should bind their sockets to a specific
  source address such that the selection code is never hit.
  
- if subtree routes do exist, the source address selection code now repeats
  the routing lookup done before source address selection is entered, except
  with the source address under consideration filled in.  This lookup will hit
  the subtree routes that were installed (see first item), giving a fresh
  dst_entry.  If the new dst_entry matches the original dst_entry, that means
  the original router has in fact sent RAs with PIOs for this source address,
  so it is preferred.  Otherwise it is not.


There are a few caveats to consider:

- the kernel currently does not create the subtree routes mentioned in the
  first item.  This is a separate work item, partially done at the time of
  writing this.  But this can equally well be performed in userspace processing
  of RAs, e.g. NetworkManager or plain static configuration.

- since addresses can also be acquired from DHCPv6, even RA/PIO combinations
  that didn't result in the creation of any addresses (e.g. A=0) should have
  subtree routes added.  Those routes *may* be relevant for DHCPv6-generated
  addresses.
