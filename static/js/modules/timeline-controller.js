// Timeline Controller
class TimelineController {
    constructor() {
        this.currentTime = 0;
        this.startTime = 0;
        this.endTime = 0;
        this.isDragging = false;
        this.isPlaying = false;
        this.playInterval = null;
        this.allConnections = [];
        this.allHosts = new Map();

        this.setupEventListeners();
    }

    setupEventListeners() {
        const slider = document.getElementById('timelineSlider');
        const progress = document.getElementById('timelineProgress');
        const handle = progress.querySelector('.timeline-handle');

        const updatePosition = (e) => {
            const rect = slider.getBoundingClientRect();
            const x = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
            const percent = x / rect.width;

            this.currentTime = this.startTime + (this.endTime - this.startTime) * percent;
            this.updateUI();
            this.filterByTime();
        };

        handle.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            this.isDragging = true;
        });

        slider.addEventListener('mousedown', (e) => {
            updatePosition(e);
            this.isDragging = true;
        });

        document.addEventListener('mousemove', (e) => {
            if (this.isDragging) {
                updatePosition(e);
            }
        });

        document.addEventListener('mouseup', () => {
            this.isDragging = false;
        });
    }

    setTimeRange(start, end) {
        this.startTime = start;
        this.endTime = end;
        this.currentTime = start; // Start at 0.00s to show initial state

        document.getElementById('timelineStart').textContent = this.formatTime(0);
        document.getElementById('timelineEnd').textContent = this.formatTime(end - start);
        document.getElementById('timelineContainer').classList.add('active');

        this.updateUI();
        this.filterByTime(); // Apply initial filter
    }

    formatTime(seconds) {
        if (seconds < 60) {
            return seconds.toFixed(2) + 's';
        } else if (seconds < 3600) {
            const mins = Math.floor(seconds / 60);
            const secs = (seconds % 60).toFixed(0);
            return `${mins}m ${secs}s`;
        } else {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
    }

    updateUI() {
        const percent = ((this.currentTime - this.startTime) / (this.endTime - this.startTime)) * 100;
        document.getElementById('timelineProgress').style.width = percent + '%';
        document.getElementById('timelineTime').textContent = this.formatTime(this.currentTime - this.startTime);
    }

    setData(connections, hosts, packets) {
        this.allConnections = connections;
        this.allHosts = hosts;
        this.allPackets = packets || [];
    }

    filterByTime() {
        if (!visualizer) return;

        // Filter connections based on current time
        const filteredConnections = this.allConnections.filter(conn => {
            // Check if connection has started by this time
            return conn.startTime <= this.currentTime;
        });

        // Create filtered hosts based on connections up to this time
        const filteredHostIPs = new Set();
        filteredConnections.forEach(conn => {
            filteredHostIPs.add(conn.source);
            filteredHostIPs.add(conn.destination);
        });

        const filteredHosts = new Map();
        this.allHosts.forEach((host, ip) => {
            if (filteredHostIPs.has(ip)) {
                filteredHosts.set(ip, host);
            }
        });

        // Update visualizer with filtered data
        const tempParser = {
            hosts: filteredHosts,
            connections: new Map(filteredConnections.map(conn =>
                [`${conn.source}-${conn.destination}`, conn]
            ))
        };

        visualizer.loadData(tempParser);
    }

    play() {
        if (this.isPlaying) return;

        this.isPlaying = true;
        // Disable jiggle physics during play
        if (visualizer) {
            visualizer.animating = false;
        }
        this.playInterval = setInterval(() => {
            // Advance by 1 second
            this.currentTime += 1;

            // Stop if we reach the end
            if (this.currentTime >= this.endTime) {
                this.pause();
                this.currentTime = this.endTime;
            }

            this.updateUI();
            this.filterByTime();
        }, 100); // Update every 100ms for smooth animation
    }

    pause() {
        this.isPlaying = false;
        if (this.playInterval) {
            clearInterval(this.playInterval);
            this.playInterval = null;
        }
        // Re-enable jiggle physics when stopped
        if (visualizer) {
            visualizer.animating = true;
        }
    }

    togglePlay() {
        if (this.isPlaying) {
            this.pause();
        } else {
            // Reset if at end
            if (this.currentTime >= this.endTime) {
                this.currentTime = this.startTime;
            }
            this.play();
        }
        return this.isPlaying;
    }

    seekToTime(timestamp) {
        this.currentTime = timestamp;
        this.updateUI();
        this.filterByTime();
    }
}
