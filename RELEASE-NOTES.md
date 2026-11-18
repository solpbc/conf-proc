# confidential processing: image #6

this is a security fix. image #6 fixes two flaws. image #5, which is still
serving, has both until it stops serving.

CVE-2026-98432 is a flaw in how the linux kernel handles incoming connection
requests that carry IP options. anyone able to send such requests to the engine
could in principle have run their own code on it, and code running there could
reach what the engine processes while it runs. the published exploit relies on
MPTCP, a network feature the gateway (the part of the engine that accepts
connections) does not use, and no exploitation of the flaw had been reported
when we checked on november 18. image #6 runs a kernel with the fix, and its
firewall also drops those requests before they reach the gateway.

CVE-2026-15974 lets a request make the engine load images, audio or video from
an address, such as a web link or a file path, instead of from the request
itself. a request from any journal authorized to use confidential processing
could have used it to make the engine open a file that the model server's own
restricted user can read, or fetch from its own internal services. image #6
refuses any media sent as an address. your journal already includes media in the
request, so it keeps working as before.

the engine keeps no record of what requests contained or where connections came
from, so it can't show whether either flaw was used.

your journal starts using image #6 once image #6 is serving and your journal has
updated to a release that trusts it. on a phone, the solstone app needs its own
update too. until image #5 stops serving, an updated journal may still use
either.

journal releases that trust image #6 also check that the engine's amd processor
firmware meets a minimum version. image #6 moves to nvidia driver 595.91.07,
which the fixed kernel needs.

# confidential processing: image #5

released october 29, 2026.

this is a security fix. an earlier build could accept a changed disk partition
table without that change appearing in the measurements your journal checks.
someone able to alter that table could add swap space, letting memory pressure
write pieces of what you sent to disk outside protected memory. image #5 checks
the partition layout before starting services and disables automatic swap.
it also tightens network separation between the model services and the gateway.

our assessment is that nothing you sent was exposed. that is a judgment, not a
measurement of the whole system: we verified the published image used to create
the serving engine, but did not instrument the disk layout Azure presented at
boot. there is no event, signal or report suggesting a deliberate disk change
or an exploit of the serving software.

the engine now reports fixed health states to sol pbc's monitoring on Cloudflare,
independently of whether new processing connections can get through. the report
contains no request or response content, journal or sign-in identifiers, or
credentials. service-wide usage figures leave the engine without a per-journal
breakdown. collector work has a bounded deadline, so a stuck collection fails
instead of holding new connections indefinitely.

when your journal repeats the beginning of a request, the engine can reuse the
work it has already done on that beginning. authorization from the services
portal keeps this saved work separate for each journal.
