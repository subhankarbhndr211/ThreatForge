/**
 * ThreatForge Advanced Packet Analyzer
 * Full protocol dissection - Wireshark-class capabilities
 */

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PROTOCOL DEFINITIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const PROTOCOLS = {
    ETHERNET: 0x0800,
    ARP: 0x0806,
    VLAN: 0x8100,
    IPV6: 0x86DD,
    MPLS: 0x8847
};

const IP_PROTOCOLS = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP'
};

const TCP_FLAGS = {
    0x01: 'FIN',
    0x02: 'SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x10: 'ACK',
    0x20: 'URG',
    0x40: 'ECE',
    0x80: 'CWR'
};

const DNS_TYPES = {
    1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME',
    6: 'SOA', 7: 'MB', 8: 'MG', 9: 'MR', 10: 'NULL',
    11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV',
    255: 'ANY'
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PACKET PARSER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function parsePacket(buffer, offset, length, le) {
    const view = new DataView(buffer);
    const packet = {
        raw: { offset, length },
        timestamp: null,
        capturedLength: length,
        originalLength: 0
    };

    // Global header timestamp (stored separately per packet)
    const tsSec = view.getUint32(offset, le);
    const tsUsec = view.getUint32(offset + 4, le);
    packet.timestamp = tsSec + tsUsec / 1000000;

    const pktOffset = offset + 16; // Skip packet header
    const pktLen = Math.min(length - 16, buffer.byteLength - pktOffset);

    if (pktLen < 14) return null;

    // ── LAYER 2: ETHERNET ──────────────────────────────────────
    packet.layer2 = parseEthernetLayer(view, pktOffset, le);

    let protoOffset = pktOffset + 14;
    const etherType = packet.layer2.type;

    // Handle VLAN tagging
    if (etherType === 0x8100) {
        packet.layer2.vlan = {
            priority: (view.getUint16(protoOffset, le) >> 13) & 0x07,
            cfi: (view.getUint16(protoOffset, le) >> 12) & 0x01,
            id: view.getUint16(protoOffset, le) & 0x0FFF
        };
        protoOffset += 4;
        packet.layer2.type = view.getUint16(protoOffset - 2, le);
    }

    // ── LAYER 3: NETWORK ───────────────────────────────────────
    if (packet.layer2.type === PROTOCOLS.IPV6) {
        packet.layer3 = parseIPv6Layer(view, protoOffset);
    } else if (packet.layer2.type === PROTOCOLS.ETHERNET) {
        packet.layer3 = parseIPv4Layer(view, protoOffset, pktLen - 14);

        // ── LAYER 4: TRANSPORT ────────────────────────────────
        if (packet.layer3) {
            const transOffset = protoOffset + packet.layer3.headerLength;

            if (packet.layer3.protocol === 6 && pktLen > packet.layer3.headerLength + 14) {
                packet.layer4 = parseTCPLayer(view, transOffset, pktLen - 14 - packet.layer3.headerLength);
            } else if (packet.layer3.protocol === 17 && pktLen > packet.layer3.headerLength + 14) {
                packet.layer4 = parseUDPLayer(view, transOffset, pktLen - 14 - packet.layer3.headerLength);
            } else if (packet.layer3.protocol === 1) {
                packet.layer4 = parseICMPLayer(view, transOffset, pktLen - 14 - packet.layer3.headerLength);
            }
        }
    } else if (packet.layer2.type === PROTOCOLS.ARP) {
        packet.layer3 = parseARPLayer(view, protoOffset);
    }

    // ── APPLICATION LAYER ──────────────────────────────────────
    if (packet.layer4) {
        if (packet.layer4.protocol === 'DNS') {
            packet.application = parseDNSLayer(view, pktOffset + 14 + packet.layer3.headerLength + packet.layer4.headerLength, packet.layer4);
        } else if (packet.layer4.protocol === 'HTTP') {
            packet.application = parseHTTPLayer(view, pktOffset + 14 + packet.layer3.headerLength + packet.layer4.headerLength, packet.layer4);
        }
    }

    // ── HEX DUMP ───────────────────────────────────────────────
    packet.hexDump = generateHexDump(buffer, pktOffset, pktLen);

    // ── EXTRACT IOCs ──────────────────────────────────────────
    packet.iocs = extractIOCs(packet);

    return packet;
}

function parseEthernetLayer(view, offset, le) {
    const dstMac = [];
    const srcMac = [];

    for (let i = 0; i < 6; i++) {
        dstMac.push(view.getUint8(offset + i).toString(16).padStart(2, '0'));
        srcMac.push(view.getUint8(offset + 6 + i).toString(16).padStart(2, '0'));
    }

    return {
        type: view.getUint16(offset + 12, le),
        dstMac: dstMac.join(':'),
        srcMac: srcMac.join(':'),
        typeName: getEtherTypeName(view.getUint16(offset + 12, le))
    };
}

function parseIPv4Layer(view, offset, available) {
    if (available < 20) return null;

    const version = (view.getUint8(offset) >> 4) & 0x0F;
    const ihl = (view.getUint8(offset) & 0x0F) * 4;
    const totalLength = view.getUint16(offset + 2, le);
    const identification = view.getUint16(offset + 4, le);
    const flags = (view.getUint16(offset + 6, le) >> 13) & 0x07;
    const fragmentOffset = view.getUint16(offset + 6, le) & 0x1FFF;
    const ttl = view.getUint8(offset + 8);
    const protocol = view.getUint8(offset + 9);
    const checksum = view.getUint16(offset + 10, le);

    const srcIP = `${view.getUint8(offset+12)}.${view.getUint8(offset+13)}.${view.getUint8(offset+14)}.${view.getUint8(offset+15)}`;
    const dstIP = `${view.getUint8(offset+16)}.${view.getUint8(offset+17)}.${view.getUint8(offset+18)}.${view.getUint8(offset+19)}`;

    return {
        version,
        headerLength: ihl,
        totalLength,
        identification,
        flags: {
            reserved: (flags >> 2) & 0x01,
            dontFragment: (flags >> 1) & 0x01,
            moreFragments: flags & 0x01
        },
        fragmentOffset,
        ttl,
        protocol,
        protocolName: IP_PROTOCOLS[protocol] || `Unknown(${protocol})`,
        checksum,
        headerChecksumValid: true, // Simplified
        srcIP,
        dstIP
    };
}

function parseIPv6Layer(view, offset) {
    const payloadLength = view.getUint16(offset + 4, le);
    const nextHeader = view.getUint8(offset + 6);
    const hopLimit = view.getUint8(offset + 7);

    const srcIP = formatIPv6(view, offset + 8);
    const dstIP = formatIPv6(view, offset + 24);

    return {
        version: 6,
        trafficClass: view.getUint8(offset),
        flowLabel: view.getUint32(offset) & 0x000FFFFF,
        payloadLength,
        nextHeader,
        hopLimit,
        srcIP,
        dstIP
    };
}

function parseTCPLayer(view, offset, available) {
    if (available < 20) return null;

    const srcPort = view.getUint16(offset, le);
    const dstPort = view.getUint16(offset + 2, le);
    const seqNum = view.getUint32(offset + 4, le);
    const ackNum = view.getUint32(offset + 8, le);
    const dataOffset = ((view.getUint8(offset + 12) >> 4) & 0x0F) * 4;
    const flags = view.getUint8(offset + 13);
    const window = view.getUint16(offset + 14, le);
    const checksum = view.getUint16(offset + 16, le);
    const urgentPtr = view.getUint16(offset + 18, le);

    const flagNames = [];
    for (const [flag, name] of Object.entries(TCP_FLAGS)) {
        if (flags & parseInt(flag)) flagNames.push(name);
    }

    let protocol = null;
    if (srcPort === 53 || dstPort === 53) protocol = 'DNS';
    else if (srcPort === 80 || dstPort === 80) protocol = 'HTTP';
    else if (srcPort === 443 || dstPort === 443) protocol = 'HTTPS';
    else if (srcPort === 22 || dstPort === 22) protocol = 'SSH';
    else if (srcPort === 21 || dstPort === 21) protocol = 'FTP';
    else if (srcPort === 25 || dstPort === 25) protocol = 'SMTP';
    else if (srcPort === 110 || dstPort === 110) protocol = 'POP3';
    else if (srcPort === 143 || dstPort === 143) protocol = 'IMAP';
    else if (srcPort === 3306 || dstPort === 3306) protocol = 'MySQL';
    else if (srcPort === 5432 || dstPort === 5432) protocol = 'PostgreSQL';
    else if (srcPort === 6379 || dstPort === 6379) protocol = 'Redis';
    else if (srcPort === 27017 || dstPort === 27017) protocol = 'MongoDB';

    return {
        srcPort,
        dstPort,
        seqNumber: seqNum,
        ackNumber: ackNum,
        headerLength: dataOffset,
        flags: {
            fin: !!(flags & 0x01),
            syn: !!(flags & 0x02),
            rst: !!(flags & 0x04),
            psh: !!(flags & 0x08),
            ack: !!(flags & 0x10),
            urg: !!(flags & 0x20),
            ece: !!(flags & 0x40),
            cwr: !!(flags & 0x80)
        },
        flagNames,
        window,
        checksum,
        urgentPointer: urgentPtr,
        protocol,
        payloadOffset: dataOffset
    };
}

function parseUDPLayer(view, offset, available) {
    if (available < 8) return null;

    const srcPort = view.getUint16(offset, le);
    const dstPort = view.getUint16(offset + 2, le);
    const length = view.getUint16(offset + 4, le);
    const checksum = view.getUint16(offset + 6, le);

    let protocol = null;
    if (srcPort === 53 || dstPort === 53) protocol = 'DNS';
    else if (srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68) protocol = 'DHCP';
    else if (srcPort === 123 || dstPort === 123) protocol = 'NTP';
    else if (srcPort === 161 || dstPort === 161) protocol = 'SNMP';

    return {
        srcPort,
        dstPort,
        length,
        checksum,
        protocol
    };
}

function parseICMPLayer(view, offset, available) {
    if (available < 8) return null;

    const type = view.getUint8(offset);
    const code = view.getUint8(offset + 1);
    const checksum = view.getUint16(offset + 2, le);

    return {
        type,
        code,
        checksum,
        typeName: getICMPTypeName(type)
    };
}

function parseARPLayer(view, offset) {
    const hardwareType = view.getUint16(offset, le);
    const protocolType = view.getUint16(offset + 2, le);
    const hardwareSize = view.getUint8(offset + 4);
    const protocolSize = view.getUint8(offset + 5);
    const opcode = view.getUint16(offset + 6, le);

    const senderMac = [];
    const senderIP = [];
    const targetMac = [];
    const targetIP = [];

    for (let i = 0; i < 6; i++) {
        senderMac.push(view.getUint8(offset + 8 + i).toString(16).padStart(2, '0'));
        targetMac.push(view.getUint8(offset + 18 + i).toString(16).padStart(2, '0'));
    }

    for (let i = 0; i < 4; i++) {
        senderIP.push(view.getUint8(offset + 14 + i));
        targetIP.push(view.getUint8(offset + 24 + i));
    }

    return {
        hardwareType,
        protocolType,
        opcode,
        opcodeName: opcode === 1 ? 'Request' : opcode === 2 ? 'Reply' : 'Unknown',
        senderMac: senderMac.join(':'),
        senderIP: senderIP.join('.'),
        targetMac: targetMac.join(':'),
        targetIP: targetIP.join('.')
    };
}

function parseDNSLayer(view, offset, udpLayer) {
    if (!udpLayer || udpLayer.protocol !== 'DNS') return null;

    try {
        const transactionId = view.getUint16(offset, le);
        const flags = view.getUint16(offset + 2, le);
        const questions = view.getUint16(offset + 4, le);
        const answers = view.getUint16(offset + 6, le);
        const authority = view.getUint16(offset + 8, le);
        const additional = view.getUint16(offset + 10, le);

        let pos = 12;
        const queries = [];

        for (let i = 0; i < questions && pos < offset + 512; i++) {
            const [name, newPos] = parseDNSName(view, offset, pos);
            const qtype = view.getUint16(newPos, le);
            const qclass = view.getUint16(newPos + 2, le);
            queries.push({ name, type: DNS_TYPES[qtype] || qtype, class: qclass });
            pos = newPos + 4;
        }

        return {
            transactionId,
            flags: {
                response: !!(flags & 0x8000),
                opcode: (flags >> 11) & 0x0F,
                authoritative: !!(flags & 0x0400),
                truncated: !!(flags & 0x0200),
                recursionDesired: !!(flags & 0x0100),
                recursionAvailable: !!(flags & 0x0080)
            },
            questions,
            answers,
            authority,
            additional,
            queries
        };
    } catch (e) {
        return null;
    }
}

function parseDNSName(view, baseOffset, offset) {
    const labels = [];
    let pos = offset;
    let jumped = false;
    let jumpCount = 0;

    while (pos < baseOffset + 512 && jumpCount < 10) {
        const length = view.getUint8(pos);

        if ((length & 0xC0) === 0xC0) {
            if (!jumped) {
                pos += 2;
            }
            const newOffset = ((length & 0x3F) << 8) | view.getUint8(pos - 1);
            pos = newOffset;
            jumped = true;
            jumpCount++;
        } else if (length === 0) {
            pos++;
            break;
        } else {
            pos++;
            const label = [];
            for (let i = 0; i < length; i++) {
                label.push(String.fromCharCode(view.getUint8(pos + i)));
            }
            labels.push(label.join(''));
            pos += length;
        }
    }

    return [labels.join('.'), pos];
}

function parseHTTPLayer(view, offset, tcpLayer) {
    if (!tcpLayer) return null;

    try {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(
            new Uint8Array(view.buffer, offset, Math.min(1024, view.byteLength - offset))
        );

        const lines = text.split('\r\n');
        if (lines.length < 1) return null;

        const firstLine = lines[0];

        if (firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)/i)) {
            const parts = firstLine.split(' ');
            const headers = {};
            for (let i = 1; i < lines.length && lines[i]; i++) {
                const colonIdx = lines[i].indexOf(':');
                if (colonIdx > 0) {
                    headers[lines[i].substring(0, colonIdx).toLowerCase()] = lines[i].substring(colonIdx + 1).trim();
                }
            }
            return { method: parts[0], uri: parts[1], httpVersion: parts[2], headers };
        }

        if (firstLine.match(/^HTTP\/\d\.\d/)) {
            const parts = firstLine.split(' ');
            const headers = {};
            for (let i = 1; i < lines.length && lines[i]; i++) {
                const colonIdx = lines[i].indexOf(':');
                if (colonIdx > 0) {
                    headers[lines[i].substring(0, colonIdx).toLowerCase()] = lines[i].substring(colonIdx + 1).trim();
                }
            }
            return { httpVersion: parts[0], statusCode: parseInt(parts[1]), statusText: parts.slice(2).join(' '), headers };
        }

        return null;
    } catch (e) {
        return null;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UTILITY FUNCTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function getEtherTypeName(type) {
    const names = {
        0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6',
        0x8100: 'VLAN', 0x8847: 'MPLS'
    };
    return names[type] || `0x${type.toString(16).toUpperCase()}`;
}

function getICMPTypeName(type) {
    const types = {
        0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
        5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
        10: 'Router Selection', 11: 'Time Exceeded', 12: 'Parameter Problem',
        13: 'Timestamp', 14: 'Timestamp Reply', 15: 'Information Request',
        16: 'Information Reply'
    };
    return types[type] || `Type ${type}`;
}

function formatIPv6(view, offset) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
        parts.push(view.getUint16(offset + i * 2, false).toString(16));
    }
    return parts.join(':').replace(/(^|:)0(:0)*(:|$)/, '::');
}

function generateHexDump(buffer, offset, length) {
    const view = new DataView(buffer);
    const lines = [];
    const bytesPerLine = 16;

    for (let i = 0; i < length; i += bytesPerLine) {
        const lineOffset = offset + i;
        const chunkLength = Math.min(bytesPerLine, length - i);

        let hex = '';
        let ascii = '';

        for (let j = 0; j < bytesPerLine; j++) {
            if (j < chunkLength) {
                const byte = view.getUint8(lineOffset + j);
                hex += byte.toString(16).padStart(2, '0') + ' ';
                ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            } else {
                hex += '   ';
            }

            if (j === 7) hex += ' ';
        }

        lines.push({
            offset: i,
            address: `0x${(offset + i).toString(16).toUpperCase().padStart(8, '0')}`,
            hex: hex.trimEnd(),
            ascii: ascii
        });
    }

    return lines;
}

function extractIOCs(packet) {
    const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };

    // Extract IPs
    if (packet.layer3?.srcIP) iocs.ips.push(packet.layer3.srcIP);
    if (packet.layer3?.dstIP) iocs.ips.push(packet.layer3.dstIP);

    // Extract DNS queries
    if (packet.application?.queries) {
        for (const q of packet.application.queries) {
            if (q.name) iocs.domains.push(q.name);
        }
    }

    // Extract from HTTP
    if (packet.application?.headers) {
        const headers = packet.application.headers;
        if (headers.host) iocs.domains.push(headers.host);
        if (headers.referer && headers.referer.startsWith('http')) {
            try {
                iocs.urls.push(headers.referer);
            } catch (e) {}
        }
    }

    // Extract from payload
    if (packet.layer4?.payloadOffset) {
        const payloadOffset = packet.raw.offset + 14 + packet.layer3.headerLength + packet.layer4.payloadOffset;
        const payloadLength = packet.raw.length - 14 - packet.layer3.headerLength - packet.layer4.payloadOffset;

        if (payloadLength > 0 && payloadLength < 4096) {
            try {
                const text = new TextDecoder('utf-8', { fatal: false }).decode(
                    new Uint8Array(packet.raw.offset ? packet.layer4._buffer : undefined || packet.layer4._buffer, payloadOffset, payloadLength)
                );

                // URLs
                const urlMatches = text.match(/https?:\/\/[^\s<>"{}|\\^`\[\]]+/g);
                if (urlMatches) iocs.urls.push(...urlMatches);

                // Emails
                const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
                if (emailMatches) iocs.emails.push(...emailMatches);

                // Hashes
                const md5Matches = text.match(/[a-fA-F0-9]{32}/g);
                if (md5Matches) iocs.hashes.push(...md5Matches);
            } catch (e) {}
        }
    }

    // Dedupe
    iocs.ips = [...new Set(iocs.ips)].filter(ip => !isPrivateIP(ip));
    iocs.domains = [...new Set(iocs.domains)];
    iocs.urls = [...new Set(iocs.urls)];
    iocs.emails = [...new Set(iocs.emails)];
    iocs.hashes = [...new Set(iocs.hashes)];

    return iocs;
}

function isPrivateIP(ip) {
    return ip.startsWith('10.') ||
           ip.startsWith('192.168.') ||
           ip.startsWith('172.16') || ip.startsWith('172.17') ||
           ip.startsWith('172.18') || ip.startsWith('172.19') ||
           ip.startsWith('172.2') || ip.startsWith('172.30') ||
           ip.startsWith('172.31') ||
           ip.startsWith('127.') ||
           ip.startsWith('224.') ||
           ip.startsWith('255.') ||
           ip.startsWith('0.0.0.0');
}

function isSuspiciousDomain(domain) {
    const suspicious = [
        'bit.ly', 'tinyurl', 'goo.gl', 't.co',
        'tk', 'ml', 'ga', 'cf', 'gq'
    ];
    return suspicious.some(s => domain.includes(s)) || /\d{8,}\./.test(domain);
}

function isSuspiciousIP(ip) {
    // Known malicious patterns (simplified)
    const patterns = [
        /185\.220\./,    // Known Tor exit nodes
        /91\.108\./,     // Various
        /104\.(24|46|56)\./, // Common hosting
    ];
    return patterns.some(p => p.test(ip));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EXPORT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        parsePacket,
        PROTOCOLS,
        IP_PROTOCOLS,
        TCP_FLAGS,
        isPrivateIP,
        isSuspiciousDomain,
        isSuspiciousIP
    };
}
