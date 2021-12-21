# CIDRChecker

my implementation in Kotlin to a CIDR ip address checker.
checker maintain a static sorted list of blocked Networkranges by their
network value as UInt. when we want to check if a new ip address is blocked
or not, we are using binary search for the closer network that is smaller
than the input and check if it belongs to that ip range using AND operation
with the mask.

several points to notice:
1) CIDR ranges MUST be non-overlapping.
2) in case of wrong input, i.e: "10.0.0.256" OR "10.0.0.255/33"
assertion error will be thrown.
