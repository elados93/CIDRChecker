package main

data class NetworkRange(val network: UInt, val mask: UInt) : Comparable<NetworkRange> {
    override fun compareTo(other: NetworkRange) = network.compareTo(other.network)
}

class Checker(ranges: List<String>) {

    // regexes for validations
    private val zeroTo255 = "(\\d{1,2}|(0|1)\\d{2}|2[0-4]\\d|25[0-5])"
    private val ipv4Patt = zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255
    private val cidrPatt = ipv4Patt + "([/]3[0-2]?|[/][1-2][0-9]|[/][1-9])"
    private val ipv4Reg = ipv4Patt.toRegex()
    private val cidrReg = cidrPatt.toRegex()

    private val ranges = ranges.map { cidrToNetworkRage(it) }.sorted()

    private fun cidrToNetworkRage(cidr: String): NetworkRange {
        assert(cidrReg.matches(cidr)) { "$cidr isn't a valid CIDR address" }

        val (ip, bits) = cidr.split('/')
        val bitsInt = bits.toInt()
        val mask = ("1".repeat(bitsInt) + "0".repeat(32 - bitsInt)).toUInt(2)

        return NetworkRange(strIPtoUInt(ip).and(mask), mask)
    }

    private fun strIPtoUInt(ip: String): UInt =
            ip.split('.')
                    .reversed()
                    .map { it.toInt() }
                    .mapIndexed { i, octat -> octat.shl(i * 8) }
                    .sum()
                    .toUInt()

    fun isAllowed(incomingIp: String): Boolean {
        assert(ipv4Reg.matches(incomingIp)) { "$incomingIp isn't a valid IPv4 address" }

        // fast exit path: all allowed.
        if (ranges.size == 0) {
            return true
        }

        val ipUInt = strIPtoUInt(incomingIp)
        var index = ranges.binarySearch { it.network.compareTo(ipUInt) }
        if (index >= 0) {
            // ip mathced exactlly to blocked network, no need for mask check.
            return false
        }

        // find the "invertedInsertionPoint"
        index = -(index + 1)
        if (index == 0) {
            // ip is smaller than smallest netwrok ip, no need for mask check.
            return true
        }

        // get the largest network that smaller than incoming ip.
        index--

        val networkrange = ranges[index]
        return ipUInt.and(networkrange.mask) != networkrange.network
    }
}

fun main() {
    val checker =
            Checker(
                    listOf(
                            "1.1.1.1/32",
                            "2.2.2.2/31",
                            "3.3.3.3/30",
                            "4.4.4.4/25",
                    )
            )

    val ips =
            listOf(
                    // low ips checks
                    Pair("0.0.0.0", true),
                    Pair("0.0.0.1", true),

                    // 1.1.1.1/32 range checks
                    Pair("1.1.1.0", true),
                    Pair("1.1.1.1", false),
                    Pair("1.1.1.2", true),
                    Pair("1.1.1.11", true),
                    Pair("1.1.1.255", true),

                    // 2.2.2.2/31 range checks
                    Pair("2.2.2.0", true),
                    Pair("2.2.2.1", true),
                    Pair("2.2.2.2", false),
                    Pair("2.2.2.3", false),
                    Pair("2.2.2.4", true),
                    Pair("2.2.2.255", true),

                    // 3.3.3.3/30 range checks
                    Pair("3.3.3.0", false),
                    Pair("3.3.3.1", false),
                    Pair("3.3.3.2", false),
                    Pair("3.3.3.3", false),
                    Pair("3.3.3.4", true),
                    Pair("3.3.3.5", true),
                    Pair("3.3.3.255", true),

                    // 4.4.4.4/25 range checks
                    Pair("4.3.255.255", true),
                    Pair("4.4.4.0", false),
                    Pair("4.4.4.1", false),
                    Pair("4.4.4.127", false),
                    Pair("4.4.4.128", true),
            )

    ips.forEach({ assert(checker.isAllowed(it.first) == it.second) })
}
