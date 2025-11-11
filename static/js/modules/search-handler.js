// Search Handler Module
// Alias for backward compatibility
window.performRealtimeSearch = performRealtimeSearchV2;

// Helper function to extract searchable text from packet data
function extractPacketText(packetData) {
    if (!packetData || packetData.length === 0) return '';

    // Check if packetData is an array or Uint8Array
    if (!Array.isArray(packetData) && !(packetData instanceof Uint8Array)) {
        console.error('[extractPacketText] Invalid packet data type:', typeof packetData);
        return '';
    }

    // Convert byte array to ASCII string (printable chars only)
    let text = '';
    for (let i = 0; i < packetData.length && i < 2000; i++) { // Increased to 2000 bytes for better coverage
        const byte = packetData[i];
        if (byte >= 32 && byte <= 126) {
            text += String.fromCharCode(byte);
        } else if (byte === 10 || byte === 13) {
            text += ' '; // Replace newlines with spaces
        }
    }
    return text.toLowerCase();
}

// Diagnostic function to test packet data extraction
window.debugPacketData = function() {
    const visualizer = window.visualizer;
    if (!visualizer || !visualizer.allPackets) {
        console.error('[Debug] No packets loaded');
        return;
    }

    console.log(`[Debug] Total packets: ${visualizer.allPackets.length}`);

    const packetsWithData = visualizer.allPackets.filter(p => p.data && p.data.length > 0);
    console.log(`[Debug] Packets with data: ${packetsWithData.length}`);

    if (packetsWithData.length > 0) {
        console.log('[Debug] Sample packets with data:');
        packetsWithData.slice(0, 5).forEach((p, idx) => {
            const text = extractPacketText(p.data);
            console.log(`  Packet ${idx + 1}:`);
            console.log(`    Data type: ${Array.isArray(p.data) ? 'Array' : p.data.constructor.name}`);
            console.log(`    Length: ${p.data.length} bytes`);
            console.log(`    Extracted text (first 300 chars): ${text.substring(0, 300)}`);
            console.log(`    Source: ${p.source} -> Destination: ${p.destination}`);
        });
    }

    return {
        totalPackets: visualizer.allPackets.length,
        packetsWithData: packetsWithData.length,
        sampleExtracted: packetsWithData.length > 0 ? extractPacketText(packetsWithData[0].data).substring(0, 500) : ''
    };
};

// Manual test function to trigger UI search
window.testUISearch = function(searchTerm) {
    console.log('[testUISearch] Triggering search for:', searchTerm);

    // Check if elements exist
    const searchInput = document.getElementById('searchInput');
    const searchResults = document.getElementById('searchResults');
    const searchContainer = document.getElementById('searchContainer');

    console.log('[testUISearch] Elements found:', {
        searchInput: !!searchInput,
        searchResults: !!searchResults,
        searchContainer: !!searchContainer
    });

    if (!searchInput || !searchResults || !searchContainer) {
        console.error('[testUISearch] Missing DOM elements!');
        return;
    }

    // Open search container
    searchContainer.classList.add('active');

    // Set search value
    searchInput.value = searchTerm;

    // Trigger search
    performRealtimeSearch(searchTerm);

    console.log('[testUISearch] Search triggered, results should be visible');
};

// Function to search for a specific string in all packets (for debugging)
window.findStringInPackets = function(searchStr) {
    const visualizer = window.visualizer;
    if (!visualizer || !visualizer.allPackets) {
        console.error('[Find] No packets loaded');
        return [];
    }

    const lowerSearch = searchStr.toLowerCase();
    const matches = [];

    console.log(`[Find] Searching for "${searchStr}" in ${visualizer.allPackets.length} packets...`);

    visualizer.allPackets.forEach((packet, idx) => {
        if (!packet.data || packet.data.length === 0) return;

        const text = extractPacketText(packet.data);
        if (text.includes(lowerSearch)) {
            const matchIndex = text.indexOf(lowerSearch);
            const start = Math.max(0, matchIndex - 50);
            const end = Math.min(text.length, matchIndex + lowerSearch.length + 50);
            const snippet = text.substring(start, end);

            matches.push({
                packetIndex: idx,
                source: packet.source,
                destination: packet.destination,
                protocol: packet.protocol,
                length: packet.data.length,
                snippet: snippet,
                matchPosition: matchIndex
            });
        }
    });

    console.log(`[Find] Found ${matches.length} packets containing "${searchStr}"`);
    matches.forEach((m, i) => {
        console.log(`  Match ${i + 1}: ${m.source} -> ${m.destination} [${m.protocol}]`);
        console.log(`    Snippet: ...${m.snippet}...`);
    });

    return matches;
};

// Helper function to check if search term is a hex pattern
function isHexPattern(searchTerm) {
    // Check if it's hex format: "ff aa bb" or "ffaabb" or "0xff 0xaa"
    const hexPattern = /^(0x)?[0-9a-f\s]+$/i;
    return hexPattern.test(searchTerm) && searchTerm.replace(/[^0-9a-f]/gi, '').length > 0;
}

// Helper function to convert hex pattern to byte array
function hexToBytes(hexString) {
    // Remove spaces, 0x prefix, and convert to byte array
    const cleaned = hexString.replace(/\s+/g, '').replace(/0x/gi, '');
    const bytes = [];
    for (let i = 0; i < cleaned.length; i += 2) {
        if (i + 1 < cleaned.length) {
            bytes.push(parseInt(cleaned.substr(i, 2), 16));
        }
    }
    return bytes;
}

// Helper function to search for byte pattern in packet data
function searchBytesInPacket(packetData, searchBytes) {
    if (!packetData || searchBytes.length === 0) return false;

    // Search for byte pattern
    for (let i = 0; i <= packetData.length - searchBytes.length; i++) {
        let match = true;
        for (let j = 0; j < searchBytes.length; j++) {
            if (packetData[i + j] !== searchBytes[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

function getSearchResults(searchTerm) {
    const results = [];
    const lowerSearch = searchTerm.toLowerCase();

    // Safety check - use window.visualizer explicitly
    const visualizer = window.visualizer;

    if (!visualizer) {
        console.warn('[Search] Visualizer not initialized yet');
        return { results: [], stats: { totalPackets: 0, packetsWithData: 0, payloadMatches: 0, metadataMatches: 0 } };
    }

    if (!visualizer.allPackets || visualizer.allPackets.length === 0) {
        console.warn('[Search] No packets loaded. allPackets:', visualizer.allPackets ? visualizer.allPackets.length : 'undefined');
        return { results: [], stats: { totalPackets: 0, packetsWithData: 0, payloadMatches: 0, metadataMatches: 0 } };
    }


    // Check if search term is hex pattern
    const isHex = isHexPattern(searchTerm);
    const searchBytes = isHex ? hexToBytes(searchTerm) : null;

    // Track search statistics
    let metadataMatches = 0;

    // Search in nodes (IP addresses and DNS hostnames) - only for non-hex searches
    if (!isHex) {
        visualizer.nodes.forEach(node => {
            const ipMatch = node.ip.toLowerCase().includes(lowerSearch);
            const hostnameMatch = node.hostname && node.hostname.toLowerCase().includes(lowerSearch);

            if (ipMatch || hostnameMatch) {
                const displayValue = node.hostname ? `${node.hostname} (${node.ip})` : node.ip;
                results.push({
                    type: 'host',
                    value: displayValue,
                    detail: `Packets: ${node.packetsSent + node.packetsReceived} | Connections: ${node.connections.size}`,
                    data: node
                });
            }
        });
    }

    // Search in packets (metadata and payload)
    let payloadMatches = 0;
    let packetsWithData = 0;
    let sampleTexts = [];

    visualizer.allPackets.forEach((packet, idx) => {
        if (results.length >= 200) return; // Increased limit to show more results

        // Debug: count packets with data
        if (packet.data && packet.data.length > 0) {
            packetsWithData++;
            if (sampleTexts.length < 3) {
                const sampleText = extractPacketText(packet.data);
                if (sampleText.length > 0) {
                    sampleTexts.push(sampleText.substring(0, 100));
                }
            }
        }

        let matched = false;
        let matchType = 'metadata';

        if (isHex) {
            // Hex search - only search in packet data
            if (packet.data && packet.data.length > 0) {
                if (searchBytesInPacket(packet.data, searchBytes)) {
                    matched = true;
                    matchType = 'hex';
                }
            }
        } else {
            // Text search - check metadata fields first
            const matchFields = [
                packet.source,
                packet.destination,
                packet.protocol,
                packet.srcPort?.toString(),
                packet.dstPort?.toString()
            ].filter(Boolean);

            matched = matchFields.some(field => field.toLowerCase().includes(lowerSearch));

            if (matched) {
                metadataMatches++;
            }

            // If not matched in metadata, search in packet payload
            if (!matched && packet.data && packet.data.length > 0) {
                const packetText = extractPacketText(packet.data);
                if (packetText.includes(lowerSearch)) {
                    matched = true;
                    matchType = 'payload';
                }
            }
        }

        if (matched) {
            // Find a snippet of the matching text in payload
            let detailText = `${packet.protocol} | ${packet.length} bytes`;

            if (matchType === 'payload') {
                const packetText = extractPacketText(packet.data);
                const matchIndex = packetText.indexOf(lowerSearch);
                if (matchIndex !== -1) {
                    // Extract a snippet around the match
                    const start = Math.max(0, matchIndex - 20);
                    const end = Math.min(packetText.length, matchIndex + lowerSearch.length + 20);
                    let snippet = packetText.substring(start, end).trim();
                    if (start > 0) snippet = '...' + snippet;
                    if (end < packetText.length) snippet = snippet + '...';
                    detailText = `Payload: "${snippet}"`;
                }
                payloadMatches++;
            } else if (matchType === 'hex') {
                detailText = `Hex pattern found in packet data`;
            } else {
                detailText += ` | Port ${packet.srcPort || 'N/A'} → ${packet.dstPort || 'N/A'}`;
            }

            results.push({
                type: 'packet',
                value: `${packet.source} → ${packet.destination}`,
                detail: detailText,
                data: packet
            });
        }
    });


    // Remove exact duplicates but keep packets with different content
    const uniqueResults = [];
    const seen = new Set();

    for (const result of results) {
        // For packets, include packet index in key to avoid over-deduplication
        const key = result.type === 'packet'
            ? `${result.type}:${result.value}:${result.data?.timestamp || Math.random()}`
            : `${result.type}:${result.value}`;

        if (!seen.has(key)) {
            seen.add(key);
            uniqueResults.push(result);
            if (uniqueResults.length >= 50) break;
        }
    }

    return {
        results: uniqueResults,
        stats: {
            totalPackets: visualizer.allPackets.length,
            packetsWithData: packetsWithData,
            payloadMatches: payloadMatches,
            metadataMatches: metadataMatches,
            totalMatches: uniqueResults.length
        }
    };
}

function performRealtimeSearchV2(searchTerm) {
    const searchResults = document.getElementById('searchResults');
    if (!searchResults) return;

    const searchData = getSearchResults(searchTerm);
    const results = searchData.results;
    const stats = searchData.stats;

    if (results.length === 0) {
        searchResults.innerHTML = `
            <div class="search-stats" style="padding: 10px; background: rgba(255,100,100,0.1); border-bottom: 1px solid rgba(255,100,100,0.3);">
                <div style="font-weight: bold; margin-bottom: 4px;">🔍 No Results Found</div>
                <div style="font-size: 11px; opacity: 0.8;">Searched ${stats.totalPackets.toLocaleString()} packets</div>
                <div style="font-size: 11px; opacity: 0.8;">Packets with payload data: ${stats.packetsWithData.toLocaleString()}</div>
            </div>
            <div class="search-no-results">No matches for "${searchTerm}"</div>
        `;
        searchResults.classList.add('active');
        return;
    }

    let html = `
        <div class="search-stats" style="padding: 10px; background: rgba(0,153,255,0.1); border-bottom: 1px solid rgba(0,153,255,0.3); position: sticky; top: 0; z-index: 10;">
            <div style="font-weight: bold; margin-bottom: 4px;">🔍 Search Results: "${searchTerm}"</div>
            <div style="font-size: 11px; opacity: 0.8; display: flex; gap: 15px; flex-wrap: wrap;">
                <span>📊 Total Matches: <strong>${stats.totalMatches}</strong></span>
                <span>📦 Searched: <strong>${stats.totalPackets.toLocaleString()}</strong> packets</span>
                ${stats.payloadMatches > 0 ? `<span>📄 Payload Matches: <strong>${stats.payloadMatches}</strong></span>` : ''}
                ${stats.metadataMatches > 0 ? `<span>🏷️ Metadata Matches: <strong>${stats.metadataMatches}</strong></span>` : ''}
            </div>
        </div>
    `;

    results.forEach((result, idx) => {
        const typeIcon = result.type === 'host' ? '🖥️' : '📦';
        const typeLabel = result.type === 'host' ? 'Host' : 'Packet';
        html += `
            <div class="search-result-item" onclick="selectSearchResultByIndex(${idx})" style="cursor: pointer; padding: 10px; border-bottom: 1px solid rgba(150,150,150,0.2); transition: background 0.2s;" onmouseover="this.style.background='rgba(0,153,255,0.1)'" onmouseout="this.style.background='transparent'">
                <div class="search-result-type" style="font-size: 10px; color: #0099ff; font-weight: bold;">${typeIcon} ${typeLabel.toUpperCase()}</div>
                <div class="search-result-value" style="font-size: 13px; font-weight: bold; margin: 4px 0; font-family: monospace;">${result.value}</div>
                <div class="search-result-detail" style="font-size: 11px; opacity: 0.8;">${result.detail}</div>
            </div>
        `;
    });

    searchResults.innerHTML = html;
    searchResults.classList.add('active');

    // Store results for selection
    window.currentSearchResults = results;
}

function selectSearchResultByIndex(index) {
    if (window.currentSearchResults && window.currentSearchResults[index]) {
        selectSearchResult(window.currentSearchResults[index]);
    }
}

function selectSearchResult(result, searchTerm = null) {
    const searchResults = document.getElementById('searchResults');
    searchResults.classList.remove('active');

    const visualizer = window.visualizer;
    if (!visualizer) {
        console.error('[Search] Visualizer not available');
        return;
    }

    if (result.type === 'host') {
        visualizer.focusOnNode(result.data.ip);
    } else if (result.type === 'packet') {
        // Show the packet details immediately with search term highlighted
        const searchInput = document.getElementById('searchInput');
        const highlightTerm = searchTerm || searchInput.value.trim();
        visualizer.showPacketDetails(result.data, highlightTerm);

        // Also focus on the connection visually
        visualizer.focusOnConnection(result.data.source, result.data.destination);
    }
}
