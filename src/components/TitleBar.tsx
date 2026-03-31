import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";

const appWindow = getCurrentWindow();

export function TitleBar() {
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    const updateMaximized = async () => {
      setIsMaximized(await appWindow.isMaximized());
    };
    updateMaximized();
    
    // Listen for resize changes
    const unlisten = appWindow.onResized(() => {
      updateMaximized();
    });
    
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  return (
    <div 
      className="h-8 bg-[#09090b] border-b border-zinc-800 flex items-center justify-between px-3 select-none shrink-0 z-[100] relative pt-px"
    >
      {/* Draggable Area - Background layer */}
      <div data-tauri-drag-region className="absolute inset-0 z-0 bg-transparent" onDoubleClick={() => appWindow.toggleMaximize()} />

      <div className="flex items-center gap-2.5 pointer-events-none relative z-20">
        <img src="/app-icon.png" className="w-6 h-6 object-contain" alt="SDP Catcher Logo" />
        <span className="text-[0.6875rem] font-bold text-zinc-500 tracking-[0.12em] uppercase">SDP Catcher</span>
        <span className="text-xs text-white/40 font-mono tracking-wider">v1.0.2-4</span>
      </div>

      <div className="flex items-center h-full relative z-20">
        <button
          onClick={() => {
            console.log("Minimize clicked");
            appWindow.minimize();
          }}
          className="h-full px-3 flex items-center justify-center hover:bg-zinc-800 transition-colors text-zinc-400 hover:text-white"
          title="Minimize"
        >
          <Minus size={14} />
        </button>
        <button
          onClick={() => {
            console.log("Toggle Maximize clicked");
            appWindow.toggleMaximize();
          }}
          className="h-full px-3 flex items-center justify-center hover:bg-zinc-800 transition-colors text-zinc-400 hover:text-white"
          title={isMaximized ? "Restore" : "Maximize"}
        >
          <Square size={12} />
        </button>
        <button
          onClick={() => {
            console.log("Close clicked");
            appWindow.close();
          }}
          className="h-full px-3 flex items-center justify-center hover:bg-red-600/80 transition-colors text-zinc-400 hover:text-white"
          title="Close"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
