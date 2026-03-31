import { useState, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { Check } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { InterfaceList } from "./components/InterfaceList";
import { StreamTree } from "./components/StreamTree";
import { SdpViewer } from "./components/SdpViewer";
import { TitleBar } from "./components/TitleBar";
import { ptpIdToMac } from "./utils/network";

export interface Stream {
  id: string;
  name: string;
  multicastIp: string;
  sdpContent: string;
  lastSeen: number;
  mac: string;
  manufacturer: string;
  sapTimeoutMs: number;
  isGhost?: boolean;
}

export interface Device {
  name: string;
  ip: string;
  mac: string;
  manufacturer: string;
  sapTimeoutMs: number;
  streams: Stream[];
  isGhost?: boolean;
}

interface SdpDiscoveredEvent {
  source_ip: string;
  device_name: string;
  sdp_content: string;
  mac: string;
  manufacturer: string;
  sap_timeout_ms: number;
}

export interface InterfaceInfo {
  name: string;
  ip: string;
  mask: string;
}


function App() {
  const [activeIp, setActiveIp] = useState<string | null>(null);
  const activeIpRef = useRef(activeIp);
  const [zoomLevel, setZoomLevel] = useState<number>(1.0);
  const [copyToast, setCopyToast] = useState<{ x: number, y: number, visible: boolean } | null>(null);

  useEffect(() => {
    let timeout: any;
    const handleShowToast = (e: Event) => {
      const customEvent = e as CustomEvent<{ x: number, y: number }>;
      // Force a reset if clicking rapidly at the same spot
      setCopyToast(null);
      
      // Wait for a micro-tick to restart the CSS animation
      setTimeout(() => {
        setCopyToast({ x: customEvent.detail.x, y: customEvent.detail.y, visible: true });
      }, 10);

      if (timeout) clearTimeout(timeout);
      timeout = setTimeout(() => setCopyToast(null), 1000);
    };

    window.addEventListener('show-copy-toast', handleShowToast);
    return () => {
      window.removeEventListener('show-copy-toast', handleShowToast);
      if (timeout) clearTimeout(timeout);
    };
  }, []);

  useEffect(() => {
    activeIpRef.current = activeIp;
  }, [activeIp]);

  // Root zoom removed - using local zoom instead

  // Global Zoom Shortcuts
  useEffect(() => {
    const handleZoomKeys = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey) {
        if (e.key === '+' || e.key === '=' || e.code === 'NumpadAdd') {
          e.preventDefault();
          setZoomLevel(prev => Math.min(parseFloat((prev + 0.1).toFixed(1)), 1.3));
        } else if (e.key === '-' || e.key === '6' || e.code === 'NumpadSubtract') {
          e.preventDefault();
          setZoomLevel(prev => Math.max(parseFloat((prev - 0.1).toFixed(1)), 1.0));
        }
      }
    };

    window.addEventListener('keydown', handleZoomKeys, { passive: false });
    return () => window.removeEventListener('keydown', handleZoomKeys);
  }, []);
  const [isSniffing, setIsSniffing] = useState(false);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedStream, setSelectedStream] = useState<Stream | null>(null);
  const [unknownTimeout, setUnknownTimeout] = useState(60);
  const [footerDisplayMode, setFooterDisplayMode] = useState<'auto' | 'name' | 'ip' | 'mac'>('auto');
  const [lastPtpInfo, setLastPtpInfo] = useState({ ptp_id: '---', name: '---', ip: '---' });
  const [lastPtpUpdate, setLastPtpUpdate] = useState(0);
  const [isPtpActive, setIsPtpActive] = useState(false);
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [arpTable, setArpTable] = useState<Record<string, { ip: string; name: string }>>({});
  const previousGmcId = useRef<string | null>(null);

  const [selectedDomain, setSelectedDomain] = useState(0);
  const selectedDomainRef = useRef(selectedDomain);

  useEffect(() => {
    selectedDomainRef.current = selectedDomain;
  }, [selectedDomain]);

  const [ptpDomainDraft, setPtpDomainDraft] = useState(selectedDomain.toString());
  const [sapTimeoutDraft, setSapTimeoutDraft] = useState(unknownTimeout.toString());

  // Keep drafts in sync if underlying state changes (e.g. from init)
  useEffect(() => {
    setPtpDomainDraft(selectedDomain.toString());
  }, [selectedDomain]);

  useEffect(() => {
    setSapTimeoutDraft(unknownTimeout.toString());
  }, [unknownTimeout]);

  const parseSdp = (raw: string): { name: string; multicastIp: string; originIp: string; sessionInfo: string | null } => {
    const lines = raw.split(/\r?\n/);
    let name = "Unknown Stream";
    let multicastIp = "0.0.0.0";
    let originIp = "0.0.0.0";
    let sessionInfo: string | null = null;

    for (const line of lines) {
      if (line.startsWith("s=")) {
        name = line.substring(2).trim();
      } else if (line.startsWith("i=")) {
        sessionInfo = line.substring(2).trim();
      } else if (line.startsWith("c=IN IP4 ")) {
        const parts = line.substring(9).split("/");
        multicastIp = parts[0].trim();
      } else if (line.startsWith("o=")) {
        const parts = line.split(" ");
        if (parts.length >= 6) {
          originIp = parts[5].trim();
        }
      }
    }
    return { name, multicastIp, originIp, sessionInfo };
  };

  const refreshInterfaces = async () => {
    try {
      const ifaces = await invoke<InterfaceInfo[]>("get_network_interfaces");
      setInterfaces(ifaces);
      return ifaces;
    } catch (err) {
      console.error(err);
      return [];
    }
  };

  useEffect(() => {
    const init = async () => {
      // 1. Restore Interface Selection
      const ifaces = await refreshInterfaces();
      const savedIp = localStorage.getItem('selectedInterfaceIp');
      if (savedIp && ifaces.some(i => i.ip === savedIp)) {
        setActiveIp(savedIp);
      }

      // 2. Load Ghost Cache
      const cache = localStorage.getItem('sdp_ghost_cache');
      if (cache) {
        try {
          const parsed = JSON.parse(cache) as Device[];
          const ghosted = parsed.map(d => ({
            ...d,
            isGhost: true,
            streams: d.streams.map(s => ({ ...s, isGhost: true }))
          }));
          setDevices(ghosted);
        } catch (e) {
          console.error("Ghost cache corrupted:", e);
        }
      }
    };
    init();

    // 3. Auto-Cleanup STALE Ghost Data (120s)
    const cleanupTimer = setTimeout(() => {
      setDevices(prev => prev.filter(d => !d.isGhost));
    }, 120000);

    return () => clearTimeout(cleanupTimer);
  }, []);

  // Ghost Cache Persistence Saving (Debounced 1s)
  useEffect(() => {
    if (devices.length > 0) {
      const timer = setTimeout(() => {
        localStorage.setItem('sdp_ghost_cache', JSON.stringify(devices));
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [devices]);

  // Global Sniffing Management
  const startGlobalSniffing = async (ifaces: InterfaceInfo[]) => {
    if (ifaces.length === 0) return;
    try {
      await invoke("start_sniffing", { selectedInterfaces: ifaces });
      setIsSniffing(true);
    } catch (err) {
      console.error("Failed to start global sniffing", err);
      setIsSniffing(false);
    }
  };

  useEffect(() => {
    if (interfaces.length > 0 && !isSniffing) {
        startGlobalSniffing(interfaces);
    }
  }, [interfaces]);

  useEffect(() => {
    const unlistenSdp = listen<SdpDiscoveredEvent>("sdp-discovered", (event) => {
      const { sdp_content, mac, manufacturer, sap_timeout_ms, device_name } = event.payload;
      const { name, multicastIp, originIp, sessionInfo } = parseSdp(sdp_content);

      if (originIp === "0.0.0.0") return;

      setDevices((prev) => {
        const timestamp = Date.now();
        const existingDeviceIndex = prev.findIndex((d) => d.ip === originIp);
        const deviceName = (device_name && device_name !== "---") ? device_name : (sessionInfo || `Device ${originIp}`);

        if (existingDeviceIndex >= 0) {
          const newDevices = [...prev];
          const device = { ...newDevices[existingDeviceIndex] };
          
          device.name = deviceName;
          device.mac = mac;
          device.manufacturer = manufacturer;
          device.sapTimeoutMs = sap_timeout_ms;
          device.isGhost = false; // Transition to real

          const existingStreamIndex = device.streams.findIndex((s) => s.name === name);

          if (existingStreamIndex >= 0) {
            device.streams[existingStreamIndex] = {
              ...device.streams[existingStreamIndex],
              sdpContent: sdp_content,
              multicastIp,
              lastSeen: timestamp,
              mac,
              manufacturer,
              sapTimeoutMs: sap_timeout_ms,
              isGhost: false, // Transition to real
            };
          } else {
            device.streams.push({
              id: `${originIp}-${name}`,
              name,
              multicastIp,
              sdpContent: sdp_content,
              lastSeen: timestamp,
              mac,
              manufacturer,
              sapTimeoutMs: sap_timeout_ms,
              isGhost: false, // Transition to real
            });
          }
          newDevices[existingDeviceIndex] = device;
          return newDevices;
        } else {
          return [
            ...prev,
            {
              name: deviceName,
              ip: originIp,
              mac,
              manufacturer,
              sapTimeoutMs: sap_timeout_ms,
              isGhost: false,
              streams: [
                {
                  id: `${originIp}-${name}`,
                  name,
                  multicastIp,
                  sdpContent: sdp_content,
                  lastSeen: timestamp,
                  mac,
                  manufacturer,
                  sapTimeoutMs: sap_timeout_ms,
                  isGhost: false,
                },
              ],
            },
          ];
        }
      });
    });
 
    const unlistenDiscovery = listen<[string, { ip: string; name: string }]>(
      "discovery-update",
      (event) => {
        const [key, info] = event.payload;
        setArpTable((prev) => ({ ...prev, [key]: info }));
        
        // Rafraîchissement live du nom dans l'interface
        if (info.name && info.name !== "---") {
          setDevices(prev => prev.map(d => {
            if (d.ip === info.ip) {
              return { ...d, name: info.name };
            }
            return d;
          }));
        }
      }
    );

    const unlistenPtp = listen<{ptp_id: string, name: string, ip: string, interface_ip: string, domain: number}>("ptp-clock-update", (event) => {
      const { ptp_id, interface_ip, domain } = event.payload;
      console.log("PTP Packet Received - Domain:", domain, "Target:", selectedDomainRef.current);
      
      // Flexible IP Isolation (remove mask if present)
      const selectedIp = activeIpRef.current?.split("/")[0] || "";

      if (interface_ip !== selectedIp) return;
      if (domain !== selectedDomainRef.current) return;


      console.log("✅ GMC MATCH: ", interface_ip);

      // Trigger orange transition on GMC switch (using useRef for immediate check)
      if (previousGmcId.current !== null && ptp_id !== previousGmcId.current) {
        setIsTransitioning(true);
        setTimeout(() => setIsTransitioning(false), 1500);
      }
      previousGmcId.current = ptp_id;

      setLastPtpInfo(event.payload);
      setLastPtpUpdate(Date.now());
      setIsPtpActive(true);
    });

    return () => {
      unlistenSdp.then(f => (f as () => void)());
      unlistenDiscovery.then(f => (f as () => void)());
      unlistenPtp.then(f => (f as () => void)());
    };
  }, []);

  const cycleFooterDisplayMode = () => {
    const hasName = lastPtpInfo.name && lastPtpInfo.name !== '---';
    const hasIp = lastPtpInfo.ip && lastPtpInfo.ip !== '---';
    
    if (footerDisplayMode === 'auto') {
      if (hasIp) setFooterDisplayMode('ip');
      else setFooterDisplayMode('mac');
    } else if (footerDisplayMode === 'ip') {
      setFooterDisplayMode('mac');
    } else if (footerDisplayMode === 'mac') {
      if (hasName) setFooterDisplayMode('name');
      else if (hasIp) setFooterDisplayMode('ip');
      else setFooterDisplayMode('auto');
    } else if (footerDisplayMode === 'name') {
        setFooterDisplayMode('auto');
    }
  };

   const getFooterGmcText = () => {
    if (lastPtpInfo.ptp_id === '---') return "Searching...";
    
    // Dynamic IP/Name Resolution from discoveryTable
    const ptpId = lastPtpInfo.ptp_id;
    const resolved = arpTable[ptpId];
    
    // Use resolved info if available, otherwise fallback to last PTP packet payload
    const name = resolved?.name && resolved.name !== '---' ? resolved.name : lastPtpInfo.name;
    const ip = resolved?.ip && resolved.ip !== '---' ? resolved.ip : lastPtpInfo.ip;
    const mac = ptpIdToMac(ptpId);

    const hasName = name && name !== '---';
    const hasIp = ip && ip !== '---';

    if (footerDisplayMode === 'auto') {
      if (hasName) return name;
      if (hasIp) return ip;
      return mac;
    }
    if (footerDisplayMode === 'name') return hasName ? name : mac;
    if (footerDisplayMode === 'ip') return hasIp ? ip : mac;
    if (footerDisplayMode === 'mac') return mac;
    return mac;
  };

  // Monitor Heartbeat
  useEffect(() => {
    const monitor = setInterval(() => {
      if (Date.now() - lastPtpUpdate > 3000) {
        setIsPtpActive(false);
      }
    }, 1000);
    return () => clearInterval(monitor);
  }, [lastPtpUpdate]);

  useEffect(() => {
    const interval = setInterval(() => {
      setDevices(prev => [...prev]);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const clearOfflineStreams = () => {
    const now = Date.now();
    setDevices(prev => {
      return prev.map(device => ({
        ...device,
        streams: device.streams.filter(stream => now - stream.lastSeen <= stream.sapTimeoutMs)
      })).filter(device => device.streams.length > 0);
    });
  };

  const handleInterfaceSelect = (ip: string) => {
    if (ip === activeIp) {
        setActiveIp(null);
        localStorage.removeItem('selectedInterfaceIp');
    } else {
        setActiveIp(ip);
        localStorage.setItem('selectedInterfaceIp', ip);
    }
  };

  const handleTimeoutChange = async (val: string) => {
    const num = parseInt(val) || 0;
    setUnknownTimeout(num);
    // Persist to backend
    if (num >= 60 && num <= 300) {
        await invoke("set_unknown_timeout", { seconds: num });
    }
  };

  // Le filtrage par masque de sous-réseau a été retiré pour permettre 
  // la visibilité des équipements hors-réseau (ex: APIPA).
  // L'affichage de tous les streams capturés est forcé.
  const filteredDevices = devices;


  // Disable Context Menu Globally
  useEffect(() => {
    const disableContextMenu = (e: MouseEvent) => e.preventDefault();
    document.addEventListener('contextmenu', disableContextMenu);
    return () => document.removeEventListener('contextmenu', disableContextMenu);
  }, []);

  const handleIPInteraction = (e: React.MouseEvent, textToCopy: string, ipToOpen?: string) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.ctrlKey && ipToOpen && ipToOpen !== '---') {
      import('@tauri-apps/plugin-opener').then(({ openUrl }) => openUrl(`http://${ipToOpen}`));
    } else {
      navigator.clipboard.writeText(textToCopy);
      window.dispatchEvent(new CustomEvent('show-copy-toast', { 
        detail: { x: e.clientX, y: e.clientY } 
      }));
    }
  };

  return (
    <main 
      className="flex flex-col h-screen w-screen bg-neutral-900 text-neutral-300 font-sans antialiased overflow-hidden select-none"
    >
      <TitleBar />
      <div className="flex flex-col flex-1 overflow-hidden" style={{ zoom: zoomLevel }}>
        {/* Dynamic Workspace Container */}
        <div className="flex flex-1 overflow-x-auto overflow-y-hidden" style={{ scrollbarWidth: "none" }}>
        <InterfaceList
          activeIp={activeIp}
          isSniffing={isSniffing}
          interfaces={interfaces}
          devices={devices}
          onInterfaceSelect={handleInterfaceSelect}
          setIsSniffing={setIsSniffing}
          onRefreshInterfaces={refreshInterfaces}
          onStartSniffing={startGlobalSniffing}
          zoomLevel={zoomLevel}
        />
        <StreamTree
          devices={filteredDevices}
          onStreamSelect={setSelectedStream}
          selectedStreamId={selectedStream?.id || null}
          onClearOffline={clearOfflineStreams}
          isSniffing={isSniffing}
          globalTimeout={unknownTimeout}
        />
        <SdpViewer
          sdp={selectedStream?.sdpContent || null}
          sourceIp={selectedStream ? `${selectedStream.name} (${selectedStream.multicastIp})` : undefined}
        />
      </div>
      
      {/* Fixed Footer Bar */}
      <footer className="h-7 bg-zinc-950 border-t border-zinc-800 flex items-center justify-between px-4 z-50 shrink-0">
        <div className="flex items-center gap-6">
          {/* GMC Footer */}
          <div className="flex items-center gap-2 text-[0.625rem] font-bold">
            <div className={`w-1.5 h-1.5 rounded-full transition-all duration-300 
                            ${isTransitioning ? 'bg-orange-500 animate-pulse shadow-[0_0_10px_rgba(249,115,22,0.8)]' : 
                              isPtpActive ? 'bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 
                              'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]'}`} />
            <span className="text-neutral-500 uppercase tracking-widest">PTPV2 GMC:</span>
            <span 
              onClick={isPtpActive ? cycleFooterDisplayMode : undefined}
              onContextMenu={(e) => {
                const ptpId = lastPtpInfo.ptp_id;
                const resolved = arpTable[ptpId];
                const ip = resolved?.ip && resolved.ip !== '---' ? resolved.ip : lastPtpInfo.ip;
                handleIPInteraction(e, getFooterGmcText(), ip === '---' ? undefined : ip);
              }}
              className={`text-neutral-200 transition-colors ${isPtpActive ? 'hover:text-white cursor-pointer' : 'text-neutral-600 italic cursor-not-allowed'}`}
            >
              {isPtpActive ? getFooterGmcText() : (activeIp ? "No PTP data for this PTP Domain" : "Select Interface")}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 ml-auto">
            {/* PTP Domain Control */}
            <div className="flex items-center gap-2">
                <span className="text-[0.5625rem] text-zinc-600 font-bold uppercase tracking-wider">PTP DOMAIN</span>
                <div className="flex items-center justify-center bg-zinc-900 border border-zinc-800 rounded px-1.5 h-4.5 min-w-9">
                    <input 
                        type="text" 
                        value={ptpDomainDraft}
                        onChange={(e) => setPtpDomainDraft(e.target.value.replace(/[^0-9]/g, '').slice(0, 3))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = Math.min(255, parseInt(ptpDomainDraft) || 0);
                            setSelectedDomain(val);
                            setPtpDomainDraft(val.toString());
                            (e.target as HTMLInputElement).blur();
                          }
                        }}
                        className="w-5 bg-transparent text-[0.625rem] text-zinc-300 font-mono text-center focus:outline-none appearance-none translate-y-0.25"
                        title="0-255"
                    />
                </div>
            </div>

            {/* SAP Timeout Control */}
            <div className="flex items-center gap-2">
                <span className="text-[0.5625rem] text-zinc-600 font-bold uppercase tracking-wider">DEFAULT SAP TIMEOUT</span>
                <div className="flex items-center justify-center bg-zinc-900 border border-zinc-800 rounded px-1.5 h-4.5 min-w-9">
                    <input 
                        type="text" 
                        value={sapTimeoutDraft}
                        onChange={(e) => setSapTimeoutDraft(e.target.value.replace(/[^0-9]/g, '').slice(0, 3))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = Math.min(300, Math.max(60, parseInt(sapTimeoutDraft) || 60));
                            handleTimeoutChange(val.toString());
                            setSapTimeoutDraft(val.toString());
                            (e.target as HTMLInputElement).blur();
                          }
                        }}
                        className="w-5 bg-transparent text-[0.625rem] text-zinc-300 font-mono text-center focus:outline-none appearance-none translate-y-0.25"
                        title="60-300"
                    />
                    <span className="text-[0.5625rem] text-zinc-600 font-bold ml-0.5">s</span>
                </div>
            </div>

            {/* Zoom Controls (Minimalist) */}
            <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-800 rounded px-1 h-4.5">
              <button 
                 onClick={() => setZoomLevel(prev => Math.max(1.0, prev - 0.1))}
                 className="text-zinc-500 hover:text-white px-1 font-mono text-xs transition-colors leading-none shrink-0"
              >-</button>
              <button 
                 onClick={() => setZoomLevel(prev => Math.min(1.3, prev + 0.1))}
                 className="text-zinc-500 hover:text-white px-1 font-mono text-xs transition-colors leading-none shrink-0 pb-0.5"
              >+</button>
            </div>
        </div>
      </footer>
      </div>

      <style>{`
        @keyframes damageFloat {
          0% { opacity: 0; transform: translate(-50%, -30px) scale(0.5); }
          15% { opacity: 1; transform: translate(-50%, -36px) scale(1.1); }
          30% { transform: translate(-50%, -38px) scale(1); }
          80% { opacity: 1; transform: translate(-50%, -42px) scale(1); }
          100% { opacity: 0; transform: translate(-50%, -46px) scale(0.9); }
        }
        .animate-damage {
          animation: damageFloat 1s ease-out forwards;
        }
      `}</style>
      
      {copyToast && (
        <div 
          key={`${copyToast.x}-${copyToast.y}`}
          className="fixed z-9999 pointer-events-none"
          style={{ left: copyToast.x, top: copyToast.y }}
        >
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-zinc-800 text-white rounded-md shadow-xl border border-white/10 animate-damage">
            <Check size="12" className="text-green-400" />
            <span className="text-[10px] font-bold tracking-wide uppercase">Copied</span>
          </div>
        </div>
      )}
    </main>
  );
}

export default App;
