# confidential processing: image #5

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
