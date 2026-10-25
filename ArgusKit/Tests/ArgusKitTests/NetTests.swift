import Foundation
import Testing
@testable import ArgusKit

@Suite struct IPAddressTests {
    @Test func parsesAndFormats() {
        #expect(IPAddress("192.168.1.10")?.description == "192.168.1.10")
        #expect(IPAddress("2001:db8::1")?.description == "2001:db8::1")
        #expect(IPAddress("[fe80::1%en0]")?.isLinkLocal == true)
        #expect(IPAddress("::ffff:10.0.0.1") == IPAddress("10.0.0.1"))
        #expect(IPAddress("not an ip") == nil)
        #expect(IPAddress("256.1.1.1") == nil)
    }

    @Test func classifies() {
        #expect(IPAddress("10.1.2.3")!.isPrivate)
        #expect(IPAddress("172.16.0.1")!.isPrivate)
        #expect(!IPAddress("172.32.0.1")!.isPrivate)
        #expect(IPAddress("100.64.1.1")!.isPrivate)
        #expect(IPAddress("127.0.0.1")!.isLoopback)
        #expect(IPAddress("::1")!.isLoopback)
        #expect(IPAddress("fd12::1")!.isPrivate)
        #expect(IPAddress("224.0.0.251")!.isMulticast)
        #expect(IPAddress("ff02::fb")!.isMulticast)
        #expect(!IPAddress("17.253.144.10")!.isLocalNetwork)
    }

    @Test func networksAndRanges() {
        let net = IPNetwork("10.20.0.0/16")!
        #expect(net.contains(IPAddress("10.20.255.1")!))
        #expect(!net.contains(IPAddress("10.21.0.1")!))
        #expect(IPNetwork("10.20.30.40/8")!.description == "10.0.0.0/8")
        #expect(IPNetwork("2001:db8::/32")!.contains(IPAddress("2001:db8:ffff::1")!))
        #expect(IPNetwork("1.2.3.4/33") == nil)
        #expect(IPNetwork("0.0.0.0/0")!.contains(IPAddress("8.8.8.8")!))

        let set = IPRangeSet(networks: ["1.0.0.0/24", "1.0.1.0/24", "5.5.5.5", "2001:db8::/48"].compactMap(IPNetwork.init))
        #expect(set.v4.count == 2) // the two /24s merge
        #expect(set.contains(IPAddress("1.0.1.200")!))
        #expect(set.contains(IPAddress("5.5.5.5")!))
        #expect(!set.contains(IPAddress("5.5.5.6")!))
        #expect(set.contains(IPAddress("2001:db8:0:1::1")!))
    }
}

@Suite struct DomainSetTests {
    @Test func matchesExactAndSuffix() {
        let set = DomainSet(exact: ["ads.example.com"], suffixes: ["tracker.net"])
        #expect(set.match("ads.example.com") == .exact)
        #expect(set.match("ADS.Example.com.") == .exact)
        #expect(set.match("x.ads.example.com") == nil)
        #expect(set.match("tracker.net") == .suffix("tracker.net"))
        #expect(set.match("a.b.tracker.net") == .suffix("tracker.net"))
        #expect(set.match("nottracker.net") == nil)
    }

    @Test func normalizes() {
        #expect(DomainSet.normalize("*.Example.COM.") == "example.com")
        #expect(DomainSet.normalize("bad domain") == nil)
        #expect(DomainSet.normalize("com") == nil)
    }

    @Test func serializationRoundTrips() {
        let list = CompiledBlocklist(
            domains: DomainSet(exact: ["a.com", "b.com"], suffixes: ["c.org"]),
            addresses: IPRangeSet(networks: ["9.9.9.0/24", "2001:db8::/32"].compactMap(IPNetwork.init)))
        let restored = CompiledBlocklist(serialized: list.serialized())
        #expect(restored == list)
        #expect(CompiledBlocklist(serialized: Data([1, 2, 3])) == nil)
    }
}

@Suite struct BlocklistParserTests {
    let id = UUID()

    @Test func parsesHostsFiles() throws {
        let text = """
        # Title: Test Hosts
        127.0.0.1 localhost
        0.0.0.0 ads.example.com tracker.example.com # inline comment
        0.0.0.0 0.0.0.0
        ::1 ip6-localhost
        """
        #expect(BlocklistParser.detectFormat(text) == .hosts)
        let parsed = try BlocklistParser.parse(Data(text.utf8), format: .automatic, groupID: id)
        #expect(parsed.name == "Test Hosts")
        #expect(Set(parsed.hosts) == ["ads.example.com", "tracker.example.com"])
        #expect(parsed.compiled.domains.match("ads.example.com") == .exact)
        #expect(parsed.compiled.domains.match("sub.ads.example.com") == nil)
    }

    @Test func parsesDomainLists() throws {
        let text = """
        # comment
        ! adblock comment
        doubleclick.net
        *.wildcard.com
        ||adblock.org^
        ||scoped.org^$third-party
        address=/dnsmasq.io/0.0.0.0
        @@||allowed.com^
        """
        let parsed = try BlocklistParser.parse(Data(text.utf8), format: .automatic, groupID: id)
        #expect(Set(parsed.domains) == ["doubleclick.net", "wildcard.com", "adblock.org", "dnsmasq.io"])
        #expect(parsed.compiled.domains.match("stats.doubleclick.net") == .suffix("doubleclick.net"))
    }

    @Test func parsesAddressLists() throws {
        let text = "# firehol\n1.2.3.0/24\n5.6.7.8\n2001:db8::/32\n"
        #expect(BlocklistParser.detectFormat(text) == .addresses)
        let parsed = try BlocklistParser.parse(Data(text.utf8), format: .automatic, groupID: id)
        #expect(parsed.addresses.count == 3)
        #expect(parsed.compiled.addresses.contains(IPAddress("1.2.3.99")!))
    }

    @Test func parsesLittleSnitchRuleGroups() throws {
        let json = """
        {
          "name": "Example Group",
          "description": "Shared rules",
          "rules": [
            { "action": "allow", "process": "/Applications/Safari.app/Contents/MacOS/Safari", "remote-domains": ["apple.com", "icloud.com"], "ports": "443", "protocol": "tcp" },
            { "action": "deny", "process": "any", "remote-hosts": "telemetry.example.com", "priority": "high" },
            { "action": "allow", "process": "any", "remote": "local-net", "direction": "incoming" },
            { "action": "ask", "process": "any" }
          ],
          "denied-remote-domains": ["evil.com"],
          "denied-remote-addresses": ["66.66.66.0/24"]
        }
        """
        let parsed = try BlocklistParser.parse(Data(json.utf8), format: .automatic, groupID: id)
        #expect(parsed.name == "Example Group")
        #expect(parsed.rules.count == 4)
        #expect(parsed.rules[0].remote == .domain("apple.com"))
        #expect(parsed.rules[0].ports == .single(443))
        #expect(parsed.rules[0].proto == .tcp)
        #expect(parsed.rules[2].isPriority)
        #expect(parsed.rules[3].remote == .localNetwork)
        #expect(parsed.rules[3].direction == .incoming)
        #expect(parsed.rules.allSatisfy { $0.origin == .ruleGroup(id) })
        #expect(parsed.domains == ["evil.com"])
        // Re-parsing yields the same rule identities.
        let again = try BlocklistParser.parse(Data(json.utf8), format: .automatic, groupID: id)
        #expect(again.rules.map(\.id) == parsed.rules.map(\.id))
    }

    @Test func exportsRuleGroupsThatReimport() throws {
        let rules = [
            Rule(action: .deny, process: .path("/usr/bin/curl"), remote: .domain("example.com"), ports: .single(80), proto: .tcp),
            Rule(action: .allow, remote: .address("10.0.0.0/8")),
        ]
        let data = try BlocklistParser.exportRuleGroup(name: "Mine", description: "", rules: rules)
        let parsed = try BlocklistParser.parse(data, format: .ruleGroupJSON, groupID: id)
        #expect(parsed.rules.count == 2)
        #expect(parsed.rules[0].remote == .domain("example.com"))
        #expect(parsed.rules[1].remote == .address("10.0.0.0/8"))
    }

    @Test func rejectsEmptyLists() {
        #expect(throws: BlocklistError.empty) { try BlocklistParser.parse(Data("# nothing\n".utf8), format: .domains, groupID: id) }
    }
}

@Suite struct DNSTests {
    /// A response for www.example.com: CNAME to cdn.example.net, then an A record via compression.
    static func sampleResponse() -> Data {
        var b: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]
        let qname: [UInt8] = [3] + Array("www".utf8) + [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
        b += qname + [0, 1, 0, 1]
        // CNAME answer, name = pointer to offset 12
        b += [0xC0, 12, 0, 5, 0, 1, 0, 0, 0x0E, 0x10]
        let target: [UInt8] = [3] + Array("cdn".utf8) + [7] + Array("example".utf8) + [3] + Array("net".utf8) + [0]
        b += [0, UInt8(target.count)] + target
        let targetOffset = 12 + qname.count + 4 + 12
        // A answer for the CNAME target
        b += [0xC0, UInt8(targetOffset), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]
        return Data(b)
    }

    @Test func parsesAnswersWithCompression() throws {
        let message = try #require(DNSMessage(DNSTests.sampleResponse()))
        #expect(message.isResponse)
        #expect(message.questions == ["www.example.com"])
        #expect(message.answers.count == 2)
        #expect(message.answers[0].target == "cdn.example.net")
        #expect(message.answers[1].name == "cdn.example.net")
        let mapping = try #require(message.addressMappings.first)
        #expect(mapping.address == IPAddress("93.184.216.34"))
        #expect(mapping.hostname == "www.example.com")
    }

    @Test func parsesTCPStreams() {
        let message = DNSTests.sampleResponse()
        var stream = Data([UInt8(message.count >> 8), UInt8(message.count & 0xFF)])
        stream.append(message)
        stream.append(stream)
        #expect(DNSMessage.parseStream(stream).count == 2)
    }

    @Test func cacheRemembersNames() throws {
        var cache = DNSCache()
        cache.record(try #require(DNSMessage(DNSTests.sampleResponse())))
        #expect(cache.hostname(for: IPAddress("93.184.216.34")!) == "www.example.com")
        #expect(cache.hostname(for: IPAddress("93.184.216.34")!, now: Date().addingTimeInterval(86_400 * 2)) == nil)
    }

    @Test func rejectsGarbage() {
        #expect(DNSMessage(Data([1, 2, 3])) == nil)
        #expect(DNSMessage(Data([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12])) == nil) // pointer loop
    }
}
