// Helper function to format hex dump
function formatHexDump(data, bytesPerLine = 16) {
    if (!data || data.length === 0) return 'No data available';

    const lines = [];
    for (let i = 0; i < data.length; i += bytesPerLine) {
        // Offset
        const offset = i.toString(16).padStart(4, '0');

        // Hex bytes
        const hexBytes = [];
        const asciiBytes = [];
        for (let j = 0; j < bytesPerLine; j++) {
            if (i + j < data.length) {
                const byte = data[i + j];
                hexBytes.push(byte.toString(16).padStart(2, '0'));
                asciiBytes.push((byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.');
            } else {
                hexBytes.push('  ');
                asciiBytes.push(' ');
            }
        }

        // Format: offset  hex bytes (8) (8)  |ascii|
        const firstHalf = hexBytes.slice(0, 8).join(' ');
        const secondHalf = hexBytes.slice(8).join(' ');
        const hexPart = `${firstHalf} ${secondHalf}`.padEnd(48, ' '); // 16*2 + 15 spaces + 1 extra

        lines.push(`${offset} ${hexPart} |${asciiBytes.join('')}|`);
    }
    return lines.join('\n');
}

// Helper function to format ASCII dump
function formatAsciiDump(data) {
    if (!data || data.length === 0) return 'No data available';

    return Array.from(data).map(b =>
        (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'
    ).join('');
}

// Toggle packet data display
function togglePacketData(packetId, packetIndex) {
    const dataDiv = document.getElementById(`${packetId}-data`);
    if (!dataDiv) return;

    if (dataDiv.style.display === 'none') {
        // Show packet data
        const packet = window.currentNodePackets?.[packetIndex];
        if (packet && packet.data) {
            const hexDump = formatHexDump(packet.data);
            const asciiDump = formatAsciiDump(packet.data);

            dataDiv.innerHTML = `
                <div class="packet-data-title">Hex Dump</div>
                <div class="packet-hex-dump">${hexDump}</div>
                <div class="packet-data-title">ASCII Representation</div>
                <div class="packet-ascii-dump">${asciiDump}</div>
            `;
            dataDiv.style.display = 'block';
        } else {
            dataDiv.innerHTML = '<div style="color: #888; font-size: 10px;">No raw packet data available</div>';
            dataDiv.style.display = 'block';
        }
    } else {
        // Hide packet data
        dataDiv.style.display = 'none';
    }
}
